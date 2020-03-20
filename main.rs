#![allow(dead_code)]
#![allow(non_snake_case)]

#![warn(rust_2018_idioms)]

use std::io;
use std::env;
use std::error::Error;
use std::str;
use std::net::{SocketAddr, IpAddr};

use futures::future::try_join;
use futures::FutureExt;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::config::ResolverConfig;

const VERSION: u8 = 5;

const METH_NO_AUTH: u8 = 0;
const METH_GSSAPI: u8 = 1;
const METH_USER_PASS: u8 = 2;

const CMD_CONNECT: u8 = 1;
const CMD_BIND: u8 = 2;
const CMD_UDP_ASSOCIATE: u8 = 3;

const ATYP_IPV4: u8 = 1;
const ATYP_IPV6: u8 = 4;
const ATYP_DOMAIN: u8 = 3;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let addr = env::args().nth(1).unwrap_or_else(|| "0.0.0.0:1080".to_string());

    let mut listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).await?;

    loop {
        let (client, _addr) = listener.accept().await?;

        let serve = serve(client, resolver.clone()).map(|r| {
            if let Err(_e) = r {
                //println!("Failed to transfer; error={}", e);
            }
        });

        tokio::spawn(serve);
    }
}

async fn serve(mut client: TcpStream, resolver: TokioAsyncResolver) -> io::Result<()> {
    //==========
    // handshake
    //==========

    // version
    let ver = client.read_u8().await?;
    if ver != VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "only support socks5"));
    }

    // num of methods
    let num_methods = client.read_u8().await?;

    // methods
    let mut methods = vec![0u8; num_methods as usize];
    client.read_exact(&mut methods).await?;
    if !(methods.contains(&METH_NO_AUTH)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "only support unauth method"));
    }

    // send ack
    client.write_all(&[VERSION, METH_NO_AUTH]).await?;

    //=========
    // request
    //=========

    // read VER + CMD + RSV + ATYP
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await?;

    // version
    if buf[0] != VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "only support socks5"));
    }

    // command
    if buf[1] != CMD_CONNECT {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "only support connect command"));
    }

    // buf[2] is reserved

    // address
    let ip = match buf[3] {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).await?;
            IpAddr::from(buf)
        },
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            client.read_exact(&mut buf).await?;
            IpAddr::from(buf)
        },
        ATYP_DOMAIN => {
            let size = client.read_u8().await?;
            let mut host = vec![0u8; size as usize];
            client.read_exact(&mut host).await?;

            let host = match str::from_utf8(&host) {
                Ok(s) => s,
                _ => return Err(io::Error::new(io::ErrorKind::Other, "invalid hostname")),
            };

            let ips = resolver.lookup_ip(host).await?;
            match ips.iter().next() {
                Some(ip) => ip,
                None => return Err(io::Error::new(io::ErrorKind::Other, "lookup failed")),
            }
        },
        n => {
            let msg = format!("unknown ATYP received: {}", n);
            return Err(io::Error::new(io::ErrorKind::InvalidInput, msg));
        }
    };

    let port = client.read_u16().await?;
    let addr = SocketAddr::new(ip, port);

    //=========
    // connect
    //=========

    let remote = TcpStream::connect(addr).await;

    //==========
    // response
    //==========

    let mut resp = [0u8; 32];

    resp[0] = VERSION; // VER - protocol version
    resp[1] = match remote {
        Ok(..) => 0,
        Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
        Err(..) => 1,
    };
    resp[2] = 0; // RSV - reserved

    let pos = match addr {
        SocketAddr::V4(ref a) => {
            resp[3] = 1;
            resp[4..8].copy_from_slice(&a.ip().octets()[..]);
            8
        }
        SocketAddr::V6(ref a) => {
            resp[3] = 4;
            resp[4..20].copy_from_slice(&a.ip().octets()[..]);
            20
        }
    };
    resp[pos] = (addr.port() >> 8) as u8;
    resp[pos + 1] = addr.port() as u8;
    
    client.write_all(&resp[..pos + 2]).await?;

    //==========
    // transfer
    //==========

    let mut remote = remote?;

    let (mut ri, mut wi) = client.split();
    let (mut ro, mut wo) = remote.split();

    let client_to_remote = tokio::io::copy(&mut ri, &mut wo);
    let remote_to_client = tokio::io::copy(&mut ro, &mut wi);

    try_join(client_to_remote, remote_to_client).await?;

    Ok(())
}

