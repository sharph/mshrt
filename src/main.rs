#![allow(dead_code)]

use anyhow::{Result, anyhow};
use clap_conf::prelude::*;
use tokio::net::lookup_host;

use crate::{
    crypto::PrivateIdentity,
    tun::run_tun,
    udp::run_udp,
    websockets::{connect_websockets, listen_websockets},
};

mod crypto;
mod packetizer;
mod proto;
mod router;
mod tun;
mod udp;
mod unicast;
mod websockets;

#[cfg(test)]
mod test;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = clap_app!(mshrt =>
        (author: "Sharp Hall <sharp@sharphall.org>")
        (version: crate_version!())
        (@arg config: -c --config +takes_value "Sets a custom config file")
        (@arg private_key: -p --private_key +takes_value "base64 encoded private key")
        (@arg listen_addresses: -l --ws_listen +takes_value "A comma separated list of bind addresses")
        (@arg connect_addresses: -C --ws_connect +takes_value "A comma separated list of addresses to connect to")
        (@arg udp_listen_address: -u --udp_listen +takes_value "The UDP address to bind to")
        (@arg udp_connect_addresses: -U --udp_connect +takes_value "A comma separated list of addresses to connect to")
        (@arg tun: --tun +takes_value "Run tun interface")
    )
    .get_matches();
    let cfg = with_toml_env(&matches, ["config.toml"]);
    colog::init();
    let udp_listen = cfg
        .grab()
        .conf("udp.listen.address")
        .arg("udp_listen_address")
        .env("MESH_UDP_LISTEN_ADDRESS")
        .def("");
    let local = tokio::task::LocalSet::new();
    let private_key = cfg
        .grab()
        .conf("identity.private_key")
        .arg("private_key")
        .env("MESH_IDENTITY_PRIVATE_KEY")
        .def("");
    let id = if private_key.is_empty() {
        let new_id = PrivateIdentity::new();
        log::info!("Created new private key: {}", new_id.base64());
        new_id
    } else {
        match PrivateIdentity::from_base64(private_key.as_str()) {
            Err(e) => {
                log::error!("{}", e);
                return Err(e);
            }
            Ok(id) => id,
        }
    };
    log::info!("public id: {}", id.public_id.base64());

    local
        .run_until(async move {
            let (router_join, router_interface) = router::run_router(id.clone()).await?;

            for addr in cfg
                .grab()
                .conf("listen.addresses")
                .arg("listen_addresses")
                .env("MESH_WS_LISTEN_ADDRESSES")
                .def("")
                .split(",")
                .filter(|s| s != &"")
                .map(|s| s.to_string())
            {
                log::info!("listening websockets on {}", addr);
                listen_websockets(router_interface.clone(), id.clone(), &addr).await?;
            }

            for addr in cfg
                .grab()
                .conf("connect.addresses")
                .arg("connect_addresses")
                .env("MESH_WS_CONNECT_ADDRESSES")
                .def("")
                .split(",")
                .filter(|s| s != &"")
                .map(|s| s.to_string())
            {
                let ws_connection_interface = router_interface.clone();
                let ws_id = id.clone();
                tokio::task::spawn_local(async move {
                    loop {
                        match connect_websockets(&ws_connection_interface, ws_id.clone(), &addr)
                            .await
                        {
                            Err(e) => {
                                log::error!("{}", e);
                                break;
                            }
                            Ok(jh) => {
                                if let Err(e) = jh.await {
                                    log::error!("{}", e);
                                };
                            }
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        log::info!("reconnecting to {} over websockets", addr);
                    }
                    Ok(()) as Result<()>
                });
            }

            if !udp_listen.is_empty() {
                let udp_interface =
                    run_udp(udp_listen, router_interface.clone(), id.clone()).await?;
                for addr in cfg
                    .grab()
                    .conf("udp.connect.addresses")
                    .arg("udp_connect_addresses")
                    .env("MESH_UDP_CONNECT_ADDRESSES")
                    .def("")
                    .split(",")
                    .filter(|s| s != &"")
                    .map(|s| s.to_string())
                {
                    let udp_connection_interface = udp_interface.clone();
                    tokio::task::spawn_local(async move {
                        loop {
                            match udp_connection_interface
                                .connect(
                                    lookup_host(&addr)
                                        .await?
                                        .next()
                                        .ok_or(anyhow!("address lookup failed"))?,
                                )
                                .await
                            {
                                Err(e) => {
                                    if udp_connection_interface.is_closed() {
                                        break;
                                    }
                                    log::error!("{}", e);
                                }
                                Ok(jh) => {
                                    if let Err(e) = jh.await {
                                        log::error!("{}", e);
                                    };
                                }
                            }
                            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                            log::info!("reconnecting to {} over UDP", addr);
                        }
                        Ok(()) as Result<()>
                    });
                }
            }

            if cfg.grab().arg("tun").def("false") == "true" {
                if let Err(e) = run_tun(&id.public_id, router_interface.clone()).await {
                    log::error!("{}", e);
                    router_join.abort();
                } else {
                    log::info!("your ipv6: {}", id.public_id.to_ipv6_address());
                }
            }
            router_join.await?;
            Ok(()) as Result<()>
        })
        .await?;
    Ok(())
}
