//! NTP as an application protocol over UDP: client requests (mode 3), and a
//! stratum 2 server that answers them with its clock.

use std::any::Any;

use super::{
    AppCx, AppProtocol, AppRng, AppRole, AppSession, AppTransaction, Receive, SessionInit,
    Transport,
};
use crate::udp::ntp::{check, reply, request, timestamp, NtpCheck};
#[cfg(feature = "profile")]
use crate::Result;

/// NTP: nothing to configure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ntp;

impl AppProtocol for Ntp {
    fn name(&self) -> &str {
        "ntp"
    }

    fn describe(&self) -> String {
        "NTP requests".into()
    }

    fn default_port(&self) -> u16 {
        123
    }

    fn supports(&self, t: Transport) -> bool {
        t == Transport::Datagram
    }

    fn session(&self, init: &SessionInit) -> Box<dyn AppSession> {
        match init.role {
            AppRole::Client => Box::new(Client {
                rng: AppRng::new(init.seed),
                index: init.index,
                xmt: 0,
            }),
            AppRole::Server => Box::new(Server),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Client {
    rng: AppRng,
    index: u64,
    /// The request's transmit timestamp, which the answer echoes.
    xmt: u64,
}

impl AppSession for Client {
    fn start(&mut self, cx: &mut AppCx) {
        // Unique per transaction: the clock, and random bits and the
        // transaction number in the fraction.
        let low = (self.rng.next_u64() ^ self.index) & 0xffff_ffff;
        self.xmt = (timestamp(cx.wall()) & !0xffff_ffff) | low;
        cx.send(request(self.xmt));
    }

    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        match check(data, self.xmt) {
            NtpCheck::NotOurs => Receive::NotMine,
            NtpCheck::Reply { kiss } => {
                let label = if kiss { "kiss-o'-death" } else { "reply" };
                cx.transaction(AppTransaction::new(label, true).with_error(kiss));
                cx.close();
                Receive::Taken
            }
        }
    }
}

struct Server;

impl AppSession for Server {
    fn receive(&mut self, data: &[u8], cx: &mut AppCx) -> Receive {
        match reply(data, timestamp(cx.wall())) {
            Some(r) => {
                cx.send(r);
                cx.transaction(AppTransaction::new("reply", true));
                Receive::Taken
            }
            None => Receive::NotMine,
        }
    }
}

/// Reads an `[ntp]` table, which has nothing in it yet.
#[cfg(feature = "profile")]
pub fn parse(t: &toml::Table) -> Result<Ntp> {
    match t.keys().next() {
        Some(k) => Err(crate::Error::Profile(format!("unknown key `{k}`"))),
        None => Ok(Ntp),
    }
}
