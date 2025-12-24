use crate::{
    crypto::{EncryptionSession, KeyExchange, KeyExchangeMessage, PrivateIdentity, PublicIdentity},
    proto::{MeshMessage, MessagePayload, Route, UnicastMessage, UnicastMessagePayload},
    router::RouterMessage,
};
use anyhow::{Result, anyhow, bail};
use futures_util::future;
use std::collections::HashMap;
use tokio::{
    sync::mpsc::{Receiver, Sender, channel},
    task::JoinHandle,
};

static KEX1_RESEND_PERIOD: std::time::Duration = tokio::time::Duration::from_secs(1);
static UNICAST_SESSION_TIMEOUT: std::time::Duration = tokio::time::Duration::from_secs(60);

pub enum RouteManagementMessage {
    Add(Route),
    Delete(Route),
}

struct RouteObservation {
    sensor: JoinHandle<()>,
    reset_tx: Sender<()>,
    last_seen: Option<std::time::SystemTime>,
    score: u8,
    latency: std::time::Duration,
}

fn observation_task(
    our_id: PublicIdentity,
    their_id: PublicIdentity,
    route: Route,
    mesh_tx: Sender<RouterMessage>,
    immediate: bool,
) -> (JoinHandle<()>, Sender<()>) {
    let (tx, mut rx) = channel(1);
    let join_handle = tokio::task::spawn_local(async move {
        if immediate {
            let ping = MeshMessage::unicast(
                our_id.clone(),
                their_id.clone(),
                route.clone(),
                UnicastMessagePayload::Ping(0, std::time::SystemTime::now()),
            );
            let _ = mesh_tx.try_send(RouterMessage::SendMessage(ping));
        }
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    let ping = MeshMessage::unicast(
                        our_id.clone(),
                        their_id.clone(),
                        route.clone(),
                        UnicastMessagePayload::Ping(0, std::time::SystemTime::now()),
                    );
                    let _ = mesh_tx.try_send(RouterMessage::SendMessage(ping));
                },
                _ = rx.recv() => {
                }
            }
        }
    });
    (join_handle, tx)
}

impl RouteObservation {
    fn new(
        our_id: PublicIdentity,
        their_id: PublicIdentity,
        route: Route,
        tx: Sender<RouterMessage>,
        immediate: bool,
    ) -> Self {
        let (sensor, reset_tx) = observation_task(our_id, their_id, route, tx, immediate);
        Self {
            sensor,
            reset_tx,
            last_seen: None,
            score: 0,
            latency: std::time::Duration::from_secs(0),
        }
    }

    fn is_usable(&self) -> bool {
        if let Some(last) = self.last_seen {
            if let Ok(duration) = last.elapsed() {
                duration < std::time::Duration::from_secs(20)
            } else {
                false
            }
        } else {
            false
        }
    }

    fn observe(&mut self, payload: &(u16, std::time::SystemTime)) -> Result<()> {
        let now = std::time::SystemTime::now();
        self.last_seen = Some(now);
        self.latency = now.duration_since(payload.1)?;
        Ok(())
    }
}

impl Drop for RouteObservation {
    fn drop(&mut self) {
        self.sensor.abort();
    }
}

struct Routes {
    observations: HashMap<Route, RouteObservation>,
    tx: Sender<RouterMessage>,
}

impl Routes {
    fn new(tx: Sender<RouterMessage>) -> Self {
        Self {
            observations: HashMap::default(),
            tx,
        }
    }

    fn handle_message(
        &mut self,
        msg: &RouteManagementMessage,
        our_id: &PublicIdentity,
        their_id: &PublicIdentity,
        tx: &Sender<RouterMessage>,
    ) {
        match msg {
            RouteManagementMessage::Add(route) => {
                self.observations.insert(
                    route.clone(),
                    RouteObservation::new(
                        our_id.clone(),
                        their_id.clone(),
                        route.clone(),
                        tx.clone(),
                        true,
                    ),
                );
                log::debug!("unicast add route: {route:?}");
            }
            RouteManagementMessage::Delete(route) => {
                self.observations.remove(route);
                log::debug!("unicast del route: {route:?}");
            }
        }
    }

    fn has_route(&self) -> bool {
        self.observations.values().any(|r| r.is_usable())
    }

    fn get_route(&self) -> Option<&Route> {
        self.observations
            .iter()
            .find(|(_r, o)| o.is_usable())
            .map(|(r, _o)| r)
    }

    fn observe_route(&mut self, route: &Route, pong: &(u16, std::time::SystemTime)) -> Result<()> {
        if let Some(observation) = self.observations.get_mut(route) {
            observation.observe(pong)?
        }
        Ok(())
    }
}

async fn get_msg_or_block<T>(rx: &mut Receiver<T>, should_block: bool) -> Option<T> {
    if should_block {
        future::pending::<()>().await;
    }
    rx.recv().await
}

pub struct UnicastConnection {
    route_management_tx: Sender<RouteManagementMessage>,
    message_receiving_tx: Sender<MeshMessage>,
    unicast_sending_tx: Sender<UnicastMessage>,
}

impl UnicastConnection {
    pub fn is_closed(&self) -> bool {
        self.route_management_tx.is_closed()
            || self.message_receiving_tx.is_closed()
            || self.unicast_sending_tx.is_closed()
    }

    pub fn send_unicast(&self, msg: UnicastMessage) -> Result<()> {
        Ok(self.unicast_sending_tx.try_send(msg)?)
    }

    pub fn receive_mesh_message(&self, msg: MeshMessage) -> Result<()> {
        Ok(self.message_receiving_tx.try_send(msg)?)
    }

    pub async fn add_route(&self, route: Route) -> Result<()> {
        log::debug!("got new route {:?}", route);
        self.route_management_tx
            .send(RouteManagementMessage::Add(route))
            .await?;
        Ok(())
    }

    pub async fn delete_route(&self, route: Route) -> Result<()> {
        log::debug!("deleting route {:?}", route);
        self.route_management_tx
            .send(RouteManagementMessage::Delete(route))
            .await?;
        Ok(())
    }
}

#[derive(Default)]
struct CryptoState {
    decrypt_session: Option<EncryptionSession>,
    encrypt_session: Option<EncryptionSession>,
    key_exchange: Option<KeyExchange>,
    key_exchange_message_2: Option<KeyExchangeMessage>,
}

impl CryptoState {
    fn ready(&self) -> bool {
        self.encrypt_session.is_some()
    }

    fn reset_encryption_session(&mut self) {
        self.encrypt_session = None;
        self.key_exchange = None;
        self.key_exchange_message_2 = None;
    }

    fn decrypt_mesh_message(&self, msg: &MeshMessage) -> Result<UnicastMessage> {
        UnicastMessage::from_mesh_message(
            msg,
            self.decrypt_session
                .as_ref()
                .ok_or(anyhow!("no active crypto session"))?,
        )
    }

    fn encrypt_unicast_message(
        &mut self,
        to: PublicIdentity,
        msg: &UnicastMessage,
        route: Route,
    ) -> Result<MeshMessage> {
        msg.into_mesh_message(
            to,
            route,
            self.encrypt_session
                .as_mut()
                .ok_or(anyhow!("no active crypto session"))?,
        )
    }

    fn should_send_kex_1(&self) -> bool {
        self.encrypt_session.is_none()
    }

    fn get_key_exchange_1(&mut self) -> KeyExchangeMessage {
        self.key_exchange
            .get_or_insert_with(KeyExchange::new)
            .public()
    }

    fn handle_key_exchange_1(&mut self, kex_msg: &KeyExchangeMessage) -> Result<()> {
        let kex = KeyExchange::new_from_other_message(kex_msg)?;
        if let Some(kex_2) = &self.key_exchange_message_2
            && let Some(session) = &self.decrypt_session
            && kex_msg.get_session_id() == kex_2.get_session_id()
            && kex_msg.get_session_id() == session.get_session_id()
        {
            // don't recreate an already established session.
            return Ok(());
        }
        let public = kex.public();
        self.decrypt_session = Some(kex.into_encryption_session(kex_msg)?);
        log::debug!("decryption session set up!");
        self.key_exchange_message_2 = Some(public);
        Ok(())
    }

    fn has_key_exchange_2(&self) -> bool {
        self.key_exchange_message_2.is_some()
    }

    fn get_key_exchange_2(&mut self) -> Option<&KeyExchangeMessage> {
        self.key_exchange_message_2.as_ref()
    }

    fn handle_key_exchange_2(&mut self, kex_msg: &KeyExchangeMessage) -> Result<()> {
        let Some(kex) = self.key_exchange.take() else {
            log::error!("no active key exchange!");
            bail!("no active key exchange");
        };
        self.encrypt_session = Some(kex.into_encryption_session(kex_msg)?);
        log::debug!("encryption session set up!");
        Ok(())
    }
}

enum UnicastOption {
    UnicastMessage(UnicastMessage),
    MeshMessage(MeshMessage),
    RouteManagement(RouteManagementMessage),
    SendKex1,
    EndConnection,
}

pub fn run_unicast_connection(
    our_id: PrivateIdentity,
    their_id: PublicIdentity,
    tx: Sender<RouterMessage>,
) -> UnicastConnection {
    let (route_management_tx, mut route_mgmt_rx) = channel(64);
    let (message_receiving_tx, mut message_receiving_rx) = channel(64);
    let (unicast_sending_tx, mut unicast_sending_rx) = channel(64);
    let mut routes = Routes::new(tx.clone());
    log::info!("new unicast connection {:?}", their_id.base64());
    let mut crypto_state = CryptoState::default();
    let mut resend_kex_1 = tokio::time::Instant::now();
    let mut session_timeout = tokio::time::Instant::now()
        .checked_add(UNICAST_SESSION_TIMEOUT)
        .expect("expected reasonable time value");
    tokio::task::spawn_local(async move {
        loop {
            let has_route = routes.has_route();
            let ready = has_route && crypto_state.ready();
            let option = tokio::select! {
                _ = tokio::time::sleep_until(resend_kex_1), if has_route && crypto_state.should_send_kex_1() => {
                    resend_kex_1 = tokio::time::Instant::now().checked_add(KEX1_RESEND_PERIOD).expect("reasonable time value");
                    UnicastOption::SendKex1
                }
                _ = tokio::time::sleep_until(session_timeout) => {
                    UnicastOption::EndConnection
                }
                msg = unicast_sending_rx.recv(), if ready => {
                    // process messages only when encrypted path is setup
                    if let Some(msg) = msg {
                        UnicastOption::UnicastMessage(msg)
                    } else {
                        UnicastOption::EndConnection
                    }
                }
                msg = message_receiving_rx.recv() => {
                    if let Some(msg) = msg {
                        UnicastOption::MeshMessage(msg)
                    } else {
                        UnicastOption::EndConnection
                    }
                },
                msg = route_mgmt_rx.recv() => {
                    if let Some(msg) = msg {
                        UnicastOption::RouteManagement(msg)
                    } else {
                        UnicastOption::EndConnection
                    }
                }
            };
            match option {
                UnicastOption::SendKex1 => {
                    if let Some(route) = routes.get_route()
                        && let Ok(msg) = MeshMessage::unicast_sign(
                            &our_id,
                            their_id.clone(),
                            route.clone(),
                            UnicastMessagePayload::KeyExchange1(crypto_state.get_key_exchange_1()),
                        )
                    {
                        let _ = tx.send(RouterMessage::SendMessage(msg)).await;
                    }
                }
                UnicastOption::MeshMessage(msg) => {
                    let MessagePayload::Unicast(unicast_msg_payload) = &msg.payload else {
                        continue;
                    };
                    match unicast_msg_payload {
                        UnicastMessagePayload::EncryptedPayload(_) => {
                            if let Ok(uni_msg) = crypto_state.decrypt_mesh_message(&msg) {
                                // convert a message from the mesh into a local message
                                session_timeout = tokio::time::Instant::now()
                                    .checked_add(UNICAST_SESSION_TIMEOUT)
                                    .expect("expected reasonable time value");
                                let _ = tx.send(RouterMessage::ReceiveUnicast(uni_msg)).await;
                            } else if let MessagePayload::Unicast(
                                UnicastMessagePayload::EncryptedPayload(enc_msg),
                            ) = &msg.payload
                                && let Some(route) = routes.get_route()
                                && let Ok(msg_to_send) = MeshMessage::unicast_sign(
                                    &our_id,
                                    their_id.clone(),
                                    route.clone(),
                                    UnicastMessagePayload::CantDecrypt(*enc_msg.get_session_id()),
                                )
                            {
                                let _ = tx.try_send(RouterMessage::SendMessage(msg_to_send));
                            }
                        }
                        UnicastMessagePayload::CantDecrypt(session_id) => {
                            log::trace!("can't decrypt");
                            if let Some(our_session) = &crypto_state.encrypt_session
                                && our_session.get_session_id() == session_id
                                && msg.signature_valid().unwrap_or(false)
                            {
                                crypto_state.reset_encryption_session();
                            }
                        }
                        UnicastMessagePayload::KeyExchange1(kex) => {
                            log::trace!("kex1");
                            if !msg.signature_valid().unwrap_or(false) {
                                continue;
                            }
                            if let Err(e) = crypto_state.handle_key_exchange_1(kex) {
                                log::error!("{}", e);
                            };
                            if let Some(route) = routes.get_route()
                                && let Some(kex2) = crypto_state.get_key_exchange_2()
                                && let Ok(msg) = MeshMessage::unicast_sign(
                                    &our_id,
                                    their_id.clone(),
                                    route.clone(),
                                    UnicastMessagePayload::KeyExchange2(kex2.clone()),
                                )
                            {
                                let _ = tx.send(RouterMessage::SendMessage(msg)).await;
                            }
                        }
                        UnicastMessagePayload::KeyExchange2(kex) => {
                            log::trace!("kex2");
                            if !msg.signature_valid().unwrap_or(false) {
                                continue;
                            }
                            if let Err(e) = crypto_state.handle_key_exchange_2(kex) {
                                log::error!("{}", e);
                            }
                        }
                        UnicastMessagePayload::Ping(val, t) => {
                            log::trace!("ping");
                            let msg = MeshMessage::unicast(
                                our_id.public_id.clone(),
                                their_id.clone(),
                                msg.trace.clone(),
                                UnicastMessagePayload::Pong(*val, *t),
                            );
                            let _ = tx.send(RouterMessage::SendMessage(msg)).await;
                        }
                        UnicastMessagePayload::Pong(val, t) => {
                            log::trace!("pong");
                            let _ = routes.observe_route(&msg.trace, &(*val, *t));
                        }
                    }
                }
                UnicastOption::UnicastMessage(msg) => {
                    session_timeout = tokio::time::Instant::now()
                        .checked_add(UNICAST_SESSION_TIMEOUT)
                        .expect("expected reasonable time value");
                    if let Some(route) = routes.get_route()
                        && let Ok(msg) = crypto_state.encrypt_unicast_message(
                            their_id.clone(),
                            &msg,
                            route.clone(),
                        )
                    {
                        let _ = tx.send(RouterMessage::SendMessage(msg)).await;
                    }
                }
                UnicastOption::RouteManagement(msg) => {
                    routes.handle_message(&msg, &our_id.public_id, &their_id, &tx);
                }
                UnicastOption::EndConnection => break,
            };
        }
        log::info!("unicast session with {:?} ended", their_id.base64());
    });
    UnicastConnection {
        route_management_tx,
        message_receiving_tx,
        unicast_sending_tx,
    }
}
