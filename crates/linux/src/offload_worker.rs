//! Ordered nft updates kept off the NFQUEUE receive thread.
use crate::{conntrack::ConntrackKey, nft::NftPolicy};
use std::{
    collections::HashSet,
    io,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread::{self, JoinHandle},
};

enum Command {
    Block(Vec<ConntrackKey>),
    Unblock(Vec<ConntrackKey>),
}

pub enum Completion {
    Block(Vec<ConntrackKey>, io::Result<()>),
    Unblock(io::Result<()>),
}

pub struct Worker {
    commands: Sender<Command>,
    completions: Receiver<Completion>,
    thread: JoinHandle<()>,
}

impl Worker {
    pub fn start(table: String) -> io::Result<Self> {
        let (commands, pending) = mpsc::channel();
        let (finished, completions) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("rustgfw-nft".into())
            .spawn(move || {
                let nft = NftPolicy::new("/usr/sbin/nft");
                let mut installed = HashSet::new();
                while let Ok(command) = pending.recv() {
                    let result = match command {
                        Command::Block(keys) => {
                            let result = nft.block_tcp_flows(&table, &keys);
                            if result.is_ok() {
                                installed.extend(keys.iter().copied());
                            }
                            Completion::Block(keys, result)
                        }
                        Command::Unblock(keys) => {
                            let keys: Vec<_> = keys
                                .into_iter()
                                .filter(|key| installed.contains(key))
                                .collect();
                            let result = nft.unblock_tcp_flows(&table, &keys);
                            if result.is_ok() {
                                for key in keys {
                                    installed.remove(&key);
                                }
                            }
                            Completion::Unblock(result)
                        }
                    };
                    if finished.send(result).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            commands,
            completions,
            thread,
        })
    }
    pub fn block(&self, keys: Vec<ConntrackKey>) -> io::Result<()> {
        self.commands
            .send(Command::Block(keys))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "nft worker stopped"))
    }
    pub fn unblock(&self, keys: Vec<ConntrackKey>) -> io::Result<()> {
        self.commands
            .send(Command::Unblock(keys))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "nft worker stopped"))
    }
    pub fn try_completion(&self) -> io::Result<Option<Completion>> {
        match self.completions.try_recv() {
            Ok(completion) => Ok(Some(completion)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "nft worker stopped",
            )),
        }
    }
    pub fn stop(self) -> io::Result<()> {
        drop(self.commands);
        self.thread
            .join()
            .map_err(|_| io::Error::other("nft worker panicked"))
    }
}
