use anyhow::{Result, bail};
use tokio::sync::mpsc::channel;

use crate::{
    crypto::{PrivateIdentity, PublicIdentity},
    proto::{RawMessage, UnicastDestination, UnicastMessage, UnicastPayload},
    router::{RouterInterface, UntaggedConnection, run_router},
};

async fn connect_routers(
    a: RouterInterface,
    a_id: PublicIdentity,
    b: RouterInterface,
    b_id: PublicIdentity,
) -> Result<()> {
    let (a_from_mesh, b_from_net) = channel::<RawMessage>(16);
    let (b_from_mesh, a_from_net) = channel::<RawMessage>(16);
    let a_connection = UntaggedConnection(a_from_mesh, a_from_net, true);
    let b_connection = UntaggedConnection(b_from_mesh, b_from_net, false);
    a.add_connection(a_connection, Some(b_id)).await?;
    b.add_connection(b_connection, Some(a_id)).await?;
    Ok(())
}

#[tokio::test]
async fn end_to_end() -> Result<()> {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let a_id = PrivateIdentity::new();
            let b_id = PrivateIdentity::new();
            let (_jh_a, a) = run_router(a_id.clone()).await?;
            let (_jh_b, b) = run_router(b_id.clone()).await?;
            connect_routers(
                a.clone(),
                a_id.public_id.clone(),
                b.clone(),
                b_id.public_id.clone(),
            )
            .await?;
            let (unicast_tx_b, mut unicast_rx_b) = channel::<UnicastMessage>(64);
            b.add_unicast_handler(1337, unicast_tx_b).await?;
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            a.send_unicast(
                UnicastDestination::PublicIdentity(b_id.public_id),
                UnicastPayload(1337, "hello!".as_bytes().to_vec()),
            )
            .await?;
            tokio::select! {
                Some(msg) = unicast_rx_b.recv() => {
                    assert_eq!(msg.payload.1, "hello!".as_bytes().to_vec());
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                    bail!("timed out");
                }
            };

            Ok(()) as Result<()>
        })
        .await
}
