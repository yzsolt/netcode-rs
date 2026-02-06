//! Sample netcode echo client + server. This is the bare minimum needed to show a full
//! working example. Creates two threads one for the server and one for the client.
//! The main thread listens for new lines and sends them to the client with a mpsc channel.
//! The client will then send the string to the server and the server will echo it back to the
//! client. Note that since this is a UDP based protocol it's expected some messages will be dropped.
//! Once done the string "exit" will cause the client to disconnect which the server will then
//! terminate when it hears the disconnect from the client.

use netcode_rs::{
    ClientEvent, ClientId, ClientState, MAX_PAYLOAD_SIZE, ProtocolId, ServerEvent, UdpClient,
    UdpServer, generate_key,
};

use std::io::{self, BufRead};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_CLIENTS: u32 = 256; //Total number of clients we support
const PROTOCOL_ID: ProtocolId = 0x00FF_DDEE; //Unique protocol id for our application.
const TOKEN_LIFETIME: Duration = Duration::from_secs(15); //Our token lives 15 seconds.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15); // Time in seconds connection should wait before disconnecting.

const CLIENT_ID: ClientId = 0x00DD_EEFF; //Single unique client id, you'll want to tie this into
// your user store in production.

const TICK_TIME: Duration = Duration::from_millis(16); //Tick every 16ms

//Helper function for sleeping at a regular interval
fn sleep_for_tick(last_tick: &mut Instant) -> Duration {
    let now = Instant::now();

    let elapsed = (now - *last_tick).min(TICK_TIME);

    if elapsed < TICK_TIME {
        thread::sleep(TICK_TIME - elapsed);
    }

    *last_tick = now;
    TICK_TIME
}

fn main() {
    //Uncomment the below block to turn on verbose debugging for netcode
    /*
    {
        use env_logger::LogBuilder;
        use log::LogLevelFilter;

        LogBuilder::new().filter(None, LogLevelFilter::Trace).init().unwrap();
    }
    */

    let mut server =
        UdpServer::new("127.0.0.1:0", MAX_CLIENTS, PROTOCOL_ID, &generate_key()).unwrap();
    let token = server
        .generate_token(TOKEN_LIFETIME, CONNECTION_TIMEOUT, CLIENT_ID, None)
        .unwrap();

    let server_thread = thread::spawn(move || {
        let mut last = Instant::now();
        loop {
            let elapsed = sleep_for_tick(&mut last);
            server.update(elapsed);

            let mut packet = [0; MAX_PAYLOAD_SIZE];
            while let Some(event) = server.next_event(&mut packet).unwrap() {
                match event {
                    ServerEvent::ClientConnect(_id) => println!("Server: client connected"),
                    ServerEvent::ClientDisconnect(_id) => {
                        //Once our single client is done we should exit.
                        return;
                    }
                    ServerEvent::Packet(id, size) => {
                        println!("Heard packet, echoing back");
                        server.send(id, &packet[..size]).unwrap();
                    }
                    ServerEvent::SentKeepAlive(_id) | ServerEvent::ReplayRejected(_id) => {}
                    ServerEvent::RejectedClient | ServerEvent::ClientSlotFull => {}
                }
            }
        }
    });

    let mut client = UdpClient::new(&token).unwrap();

    let (tx, rx) = mpsc::channel();
    let client_thread = thread::spawn(move || {
        let mut last = Instant::now();
        loop {
            let elapsed = sleep_for_tick(&mut last);
            client.update(elapsed);

            let mut packet = [0; MAX_PAYLOAD_SIZE];
            while let Some(event) = client.next_event(&mut packet).unwrap() {
                match event {
                    ClientEvent::NewState(state) => match state {
                        ClientState::Disconnected => return,
                        s => println!("Client: new state {:?}", s),
                    },
                    ClientEvent::Packet(len) => {
                        println!("{}", String::from_utf8_lossy(&packet[..len]));
                    }
                    ClientEvent::SentKeepAlive => {}
                }
            }

            let result: Option<String> = match rx.try_recv() {
                Ok(v) => Some(v),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(_) => {
                    client.disconnect().unwrap_or(());
                    None
                }
            };

            match result {
                Some(s) if s == "exit" => {
                    client.disconnect().unwrap_or(());
                    return;
                }
                Some(s) => client.send(&s.into_bytes()).map(|_| ()).unwrap_or(()),
                None => (),
            }
        }
    });

    //Read a line from stdin and send it to our client to process.
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let value = line.unwrap();
        if value == "exit" {
            tx.send(value).unwrap();
            break;
        } else {
            tx.send(value).unwrap()
        }
    }

    client_thread.join().unwrap();
    server_thread.join().unwrap();
}
