use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::crypto::{PrivateIdentity, PublicIdentity, ShortId};
use crate::proto::{
    ConnectionId, DEFAULT_TTL, MeshMessage, MessagePayload, RawMessage, Route, TaggedRawMessage,
    UnicastDestination, UnicastMessage, UnicastPayload,
};
use crate::unicast::{UnicastConnection, run_unicast_connection};

const FLOOD_DB_SIZE: usize = 1024 * 8;

#[cfg(not(test))]
const FLOOD_ANNOUNCE_PERIOD: Duration = Duration::from_secs(10);

#[cfg(test)]
const FLOOD_ANNOUNCE_PERIOD: Duration = Duration::from_millis(100);
const FLOOD_ANNOUNCE_SEC: u64 = 1;

pub struct UntaggedConnection(
    pub mpsc::Sender<RawMessage>,
    pub mpsc::Receiver<RawMessage>,
    pub bool,
);

pub struct TaggedConnection(mpsc::Sender<RawMessage>, mpsc::Receiver<TaggedRawMessage>);

#[derive(Debug)]
struct Connection {
    connection_id: ConnectionId,
    id: Option<PublicIdentity>,
    tx: Option<mpsc::Sender<RawMessage>>,
    inbound: bool,
}

impl Connection {
    fn send_message(&mut self, message: RawMessage) -> Result<()> {
        if let Some(tx) = &self.tx {
            if !tx.is_closed() {
                if tx.try_send(message).is_err() {
                    log::error!("connection buffer full");
                }
            } else {
                log::info!("connection closed");
                self.tx = None;
            }
        }
        Ok(())
    }

    fn is_closed(&mut self) -> bool {
        if let Some(tx) = &self.tx
            && tx.is_closed()
        {
            log::info!("connection closed");
            self.tx = None;
        }
        self.tx.is_none()
    }
}

fn tag_connection(
    mut connection: UntaggedConnection,
    connection_id: ConnectionId,
) -> TaggedConnection {
    let sender = connection.0.clone();
    let (tx, rx) = mpsc::channel(1);
    tokio::task::spawn_local(async move {
        loop {
            if let Some(msg) = connection.1.recv().await {
                if tx
                    .send(TaggedRawMessage { connection_id, msg })
                    .await
                    .is_err()
                {
                    return;
                }
            } else {
                return;
            }
        }
    });
    TaggedConnection(sender, rx)
}

#[derive(Eq, PartialEq, Hash, Clone)]
struct FloodDBEntry {
    id: PublicIdentity,
    payload: MessagePayload,
}

impl FloodDBEntry {
    fn new(id: PublicIdentity, payload: MessagePayload) -> Self {
        Self { id, payload }
    }
}

#[derive(Default)]
struct FloodDB {
    db: HashMap<FloodDBEntry, std::time::Instant>,
    instants: BTreeMap<std::time::Instant, FloodDBEntry>,
}

impl FloodDB {
    fn has(&self, entry: &FloodDBEntry) -> bool {
        self.db.contains_key(entry)
    }

    fn trim(&mut self) {
        while self.db.len() > FLOOD_DB_SIZE {
            let (_, oldest) = self.instants.pop_first().unwrap();
            self.db.remove(&oldest).unwrap();
        }
    }

    fn update(&mut self, entry: FloodDBEntry) -> bool {
        let instant = Instant::now();
        let mut updated = false;
        if let Some(old_instant) = self.db.insert(entry.clone(), instant) {
            self.instants.remove(&old_instant).unwrap();
            updated = true
        }
        self.instants.insert(instant, entry);
        self.trim();
        updated
    }
}

#[derive(Eq, PartialEq, Clone, Hash)]
struct SortableByLength<T>(T);

impl<T> SortableByLength<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for SortableByLength<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for SortableByLength<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for SortableByLength<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T, X> PartialOrd for SortableByLength<T>
where
    T: PartialOrd,
    T: Eq,
    T: Ord,
    T: PartialEq,
    T: Deref<Target = VecDeque<X>>,
    X: Ord,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T, X> Ord for SortableByLength<T>
where
    T: PartialOrd,
    T: Eq,
    T: Ord,
    T: PartialEq,
    T: Deref<Target = VecDeque<X>>,
    X: Ord,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.0.len().cmp(&other.0.len()) {
            std::cmp::Ordering::Less => std::cmp::Ordering::Less,
            std::cmp::Ordering::Greater => std::cmp::Ordering::Greater,
            std::cmp::Ordering::Equal => self.0.iter().cmp(other.0.iter()),
        }
    }
}

#[derive(Default)]
struct RouteDBEntry {
    seen: BTreeMap<SortableByLength<Route>, Instant>, // btree so that length stays sorted
    unicast_connection: Option<UnicastConnection>,
}

impl RouteDBEntry {
    async fn observe(&mut self, route: &Route) {
        let now = Instant::now();
        let mut close = false;
        if self.seen.insert(route.clone().into(), now).is_none()
            && let Some(connection) = &self.unicast_connection
            && connection.add_route(route.clone()).await.is_err()
        {
            close = true;
        }
        if close {
            self.unicast_connection = None;
        }
    }

    async fn trim(&mut self, del_before: &Instant) {
        let mut close = false;
        if let Some(connection) = &self.unicast_connection {
            for (route, _instant) in self
                .seen
                .iter()
                .filter(|(_route, instant)| *instant < del_before)
            {
                if connection
                    .delete_route(route.clone().into_inner())
                    .await
                    .is_err()
                {
                    close = true;
                    break;
                }
            }
        }
        if close {
            self.unicast_connection = None;
        }
        if let Some(conn) = &self.unicast_connection
            && conn.is_closed()
        {
            self.unicast_connection = None;
        }
        self.seen.retain(|_route, instant| *instant >= *del_before);
    }

    fn shortest_route(&self) -> Option<&Route> {
        self.seen.first_key_value().map(|(k, _v)| k.deref())
    }

    fn is_empty(&self) -> bool {
        self.seen.len() == 0
    }
}

#[derive(Default)]
struct RouteDB {
    routes: BTreeMap<PublicIdentity, RouteDBEntry>,
    short_id_lookup: HashMap<ShortId, PublicIdentity>,
}

impl RouteDB {
    fn is_route_in_db(&self, id: &PublicIdentity, route: &Route) -> bool {
        if let Some(db_entry) = self.routes.get(id) {
            db_entry.seen.contains_key(&route.clone().into())
        } else {
            false
        }
    }

    fn get_route(&mut self, id: &PublicIdentity) -> Option<&mut RouteDBEntry> {
        self.routes.get_mut(id)
    }

    fn get_or_create_route(&mut self, id: &PublicIdentity) -> &mut RouteDBEntry {
        if !self.routes.contains_key(id) {
            self.routes.insert(id.clone(), RouteDBEntry::default());
        }
        self.routes.get_mut(id).unwrap()
    }

    fn get_route_for_unicast_destination(
        &mut self,
        dest: &UnicastDestination,
    ) -> Option<(PublicIdentity, &mut RouteDBEntry)> {
        match dest {
            UnicastDestination::ShortId(short_id) => {
                if let Some(id) = self.short_id_lookup.get(short_id) {
                    let id = id.clone();
                    self.get_route(&id).map(|r| (id, r))
                } else {
                    None
                }
            }
            UnicastDestination::PublicIdentity(pub_id) => {
                self.get_route(pub_id).map(|r| (pub_id.clone(), r))
            }
        }
    }

    async fn trim_routes(&mut self) {
        let Some(del_before) = Instant::now().checked_sub(FLOOD_ANNOUNCE_PERIOD.saturating_mul(3))
        else {
            return;
        };
        for (_id, route_entry) in self.routes.iter_mut() {
            route_entry.trim(&del_before).await;
        }
    }

    /// Adds route to db and returns true if route is shortest
    async fn observe_route(&mut self, id: &PublicIdentity, route: &Route) -> bool {
        let instant = Instant::now();
        self.short_id_lookup.insert(id.short_id(), id.clone());
        let rec = self.get_or_create_route(id);
        rec.observe(route).await;
        log::debug!(
            "this route {:?}, shortest {:?} for {:?}",
            route.len(),
            rec.shortest_route().map(|r| r.len()),
            id
        );
        if let Some(shortest) = rec.shortest_route()
            && shortest.len() == route.len()
        {
            true
        } else {
            false
        }
    }
}

struct RouterState {
    id: PrivateIdentity,
    connections: Vec<Connection>,
    route_db: RouteDB,
    flood_db: FloodDB,
    unicast_handlers: HashMap<u16, mpsc::Sender<UnicastMessage>>,
    tx: mpsc::Sender<RouterMessage>,
}

impl RouterState {
    fn new(id: PrivateIdentity, tx: mpsc::Sender<RouterMessage>) -> Self {
        Self {
            id,
            connections: Vec::new(),
            route_db: RouteDB::default(),
            flood_db: FloodDB::default(),
            unicast_handlers: HashMap::default(),
            tx,
        }
    }

    fn add_connection(
        &mut self,
        connection: UntaggedConnection,
        id: Option<PublicIdentity>,
        router_tx: mpsc::Sender<RouterMessage>,
    ) -> Result<()> {
        let mut append = false;
        let conn_id = ConnectionId(
            self.connections
                .iter_mut()
                .enumerate()
                .map(|(i, c)| (i.try_into(), c.is_closed()))
                .find_map(|(i, c)| if c { Some(i) } else { None })
                .unwrap_or_else(|| {
                    append = true;
                    self.connections.len().try_into()
                })
                .context("couldn't get new id for connection")?,
        );

        let inbound = connection.2;
        let TaggedConnection(tx, mut rx) = tag_connection(connection, conn_id);
        if let Some(some_id) = &id {
            if inbound {
                log::info!("adding new connection from {}", some_id.base64());
            } else {
                log::info!("adding new connection to {}", some_id.base64());
            }
        }
        let tagged = Connection {
            connection_id: conn_id,
            id,
            tx: Some(tx),
            inbound,
        };
        if append {
            log::trace!("appending connection {:?}", tagged);
            self.connections.push(tagged);
        } else {
            log::trace!("replacing connection {:?} with {:?}", conn_id, tagged);
            *self
                .connections
                .get_mut(conn_id.0 as usize)
                .expect("conn_id index should exist") = tagged;
        }
        tokio::task::spawn_local(async move {
            loop {
                if let Some(msg) = rx.recv().await {
                    if router_tx
                        .try_send(RouterMessage::IncomingMessage(msg))
                        .is_err()
                        && router_tx.is_closed()
                    {
                        return;
                    }
                } else {
                    break;
                }
            }
        });
        Ok(())
    }

    /// Returns true if a handler was replaced
    fn add_unicast_handler(&mut self, port: u16, handler: mpsc::Sender<UnicastMessage>) -> bool {
        log::debug!("registered unicast handler for port {}", port);
        self.unicast_handlers.insert(port, handler).is_some()
    }

    fn send_to_all(&mut self, msg: MeshMessage, except: Option<ConnectionId>) -> Result<()> {
        let raw_message = RawMessage::try_from(msg)?;
        for connection in self.connections.iter_mut() {
            if Some(connection.connection_id) == except {
                continue;
            }
            let _ = connection.send_message(raw_message.clone());
        }
        Ok(())
    }

    fn send_to(&mut self, msg: MeshMessage, to: ConnectionId) -> Result<()> {
        log::debug!("{msg:?} {to:?}");
        let raw_message = RawMessage::try_from(msg)?;
        let Some(connection) = self.connections.get_mut(to.0 as usize) else {
            bail!("invalid connection")
        };
        connection.send_message(raw_message.clone())?;
        Ok(())
    }

    async fn handle_flood(&mut self, msg: &MeshMessage, from: ConnectionId) -> Result<()> {
        let mut msg = msg.clone();
        if !msg.signature_valid()? {
            bail!("signature invalid");
        }
        // TODO: check flood time
        // TODO: enforce a local ttl
        if let Some(from_id) = &msg.from {
            msg.trace.push_front(from);
            let in_flood_db = self
                .flood_db
                .update(FloodDBEntry::new(from_id.clone(), msg.payload.clone()));
            let best_in_route_db = self.route_db.observe_route(from_id, &msg.trace).await;
            if (in_flood_db && !best_in_route_db) || (msg.ttl as usize) < msg.trace.len() {
                return Ok(());
            }
            self.send_to_all(msg.clone(), Some(from))?;
        }
        Ok(())
    }

    async fn send_keepalive(&mut self) {
        let hb = RawMessage::try_from(MeshMessage {
            from: None,
            to: None,
            ttl: 0,
            trace: Route::default(),
            route: Route::default(),
            payload: MessagePayload::Noop,
            signature: None,
        })
        .unwrap();
        for connection in self.connections.iter_mut() {
            let _ = connection.send_message(hb.clone());
        }
    }

    fn send_message(&mut self, mut msg: MeshMessage) -> Result<()> {
        if let MessagePayload::Unicast(_) = msg.payload {
            let dest = msg.route.pop_front().ok_or(anyhow!("no route!"))?;
            self.send_to(msg, dest)?;
        }
        Ok(())
    }

    fn send_flood(&mut self) -> Result<()> {
        let mut msg = MeshMessage {
            from: Some(self.id.public_id.clone()),
            to: None,
            ttl: DEFAULT_TTL,
            trace: Route::default(),
            route: Route::default(),
            payload: MessagePayload::Flood(std::time::SystemTime::now()),
            signature: None,
        };
        msg.sign(&self.id)?;
        self.send_to_all(msg, None)?;
        Ok(())
    }

    async fn handle_message(&mut self, msg: TaggedRawMessage) -> Result<()> {
        let conn = msg.connection_id;
        let mut msg = MeshMessage::try_from(msg.msg)?;
        match msg.payload {
            MessagePayload::Flood(_) => self.handle_flood(&msg, conn).await?,
            MessagePayload::Unicast(_) => {
                msg.trace.push_front(conn);
                if msg.to.as_ref() == Some(&self.id.public_id) || msg.route.is_empty() {
                    self.handle_unicast_for_us(msg).await?
                } else if let Some(next_hop) = msg.route.pop_front() {
                    self.send_to(msg, next_hop)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn get_unicast_connection(
        &mut self,
        dest: &UnicastDestination,
    ) -> Result<&mut UnicastConnection> {
        let Some((id, route_db_entry)) = self.route_db.get_route_for_unicast_destination(dest)
        else {
            log::debug!("no route to connect to {:?}", dest);
            bail!("no route")
        };
        if route_db_entry
            .unicast_connection
            .as_mut()
            .is_none_or(|c| c.is_closed())
        {
            log::debug!("creating new connection for {:?}", dest);
            let connection = route_db_entry
                .unicast_connection
                .insert(run_unicast_connection(self.id.clone(), id, self.tx.clone()));
            if let Some(route) = route_db_entry.seen.first_key_value() {
                let route = route.0.clone().into_inner();
                connection.add_route(route).await?;
            }
            return Ok(connection);
        } else if let Some(connection) = route_db_entry.unicast_connection.as_mut() {
            return Ok(connection);
        }
        bail!("should have returned a connection");
    }

    async fn handle_unicast_for_us(&mut self, msg: MeshMessage) -> Result<()> {
        self.get_unicast_connection(&UnicastDestination::PublicIdentity(
            msg.from.as_ref().ok_or(anyhow!("no from field"))?.clone(),
        ))
        .await?
        .receive_mesh_message(msg)?;
        Ok(())
    }

    async fn send_unicast_message(&mut self, msg: UnicastMessage) -> Result<()> {
        self.get_unicast_connection(&msg.to)
            .await?
            .send_unicast(msg)?;
        // TODO: detect closed connections
        Ok(())
    }
}

pub enum RouterMessage {
    AddConnection(UntaggedConnection, Option<PublicIdentity>),
    AddUnicastHandler(u16, mpsc::Sender<UnicastMessage>),
    IncomingMessage(TaggedRawMessage),
    SendMessage(MeshMessage),
    SendUnicast(UnicastMessage),
    ReceiveUnicast(UnicastMessage),
    SendFlood,
}

#[derive(Clone)]
pub struct RouterInterface(mpsc::Sender<RouterMessage>, PrivateIdentity);

impl RouterInterface {
    pub async fn add_connection(
        &self,
        conn: UntaggedConnection,
        id: Option<PublicIdentity>,
    ) -> Result<()> {
        Ok(self.0.send(RouterMessage::AddConnection(conn, id)).await?)
    }

    pub async fn add_unicast_handler(
        &self,
        port: u16,
        handler: mpsc::Sender<UnicastMessage>,
    ) -> Result<()> {
        Ok(self
            .0
            .send(RouterMessage::AddUnicastHandler(port, handler))
            .await?)
    }

    pub async fn send_message_to_mesh(&self, msg: MeshMessage) -> Result<()> {
        Ok(self.0.send(RouterMessage::SendMessage(msg)).await?)
    }

    pub fn try_send_message_to_mesh(&self, msg: MeshMessage) -> Result<()> {
        Ok(self.0.try_send(RouterMessage::SendMessage(msg))?)
    }

    pub async fn send_unicast(
        &self,
        to: UnicastDestination,
        payload: UnicastPayload,
    ) -> Result<()> {
        Ok(self
            .0
            .send(RouterMessage::SendUnicast(UnicastMessage::new(
                to,
                self.1.public_id.clone(),
                payload,
            )))
            .await?)
    }
}

pub async fn run_router(id: PrivateIdentity) -> Result<(JoinHandle<()>, RouterInterface)> {
    let (router_tx, mut rx) = mpsc::channel::<RouterMessage>(64);

    let mut state = RouterState::new(id.clone(), router_tx.clone());

    let tx = router_tx.clone();

    tokio::task::spawn_local(async move {
        loop {
            tokio::time::sleep(FLOOD_ANNOUNCE_PERIOD).await;
            let Ok(_) = tx.send(RouterMessage::SendFlood).await else {
                return;
            };
        }
    });

    let interface = RouterInterface(router_tx.clone(), id);

    let join_handle = tokio::task::spawn_local(async move {
        log::info!("router started!");
        loop {
            if let Some(router_msg) = rx.recv().await {
                match router_msg {
                    RouterMessage::AddConnection(conn, id) => {
                        if let Err(e) = state.add_connection(conn, id, router_tx.clone()) {
                            log::error!("{}", e);
                        }
                    }
                    RouterMessage::AddUnicastHandler(port, tx) => {
                        let _ = state.add_unicast_handler(port, tx);
                    }
                    RouterMessage::IncomingMessage(msg) => {
                        let _ = state.handle_message(msg).await;
                    }
                    RouterMessage::SendMessage(msg) => {
                        let _ = state.send_message(msg);
                    }
                    RouterMessage::SendUnicast(msg) => {
                        let _ = state.send_unicast_message(msg).await;
                    }
                    RouterMessage::ReceiveUnicast(msg) => {
                        if let Some(unicast_tx) = state.unicast_handlers.get_mut(&msg.payload.0) {
                            let _ = unicast_tx.try_send(msg);
                        } else {
                            log::trace!("unhandled unicast: {msg:?}");
                        }
                    }
                    RouterMessage::SendFlood => {
                        let _ = state.send_flood();
                        state.route_db.trim_routes().await;
                    }
                }
            }
        }
    });
    Ok((join_handle, interface))
}
