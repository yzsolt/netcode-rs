const REPLAY_BUFFER_SIZE: usize = 256;
const EMPTY_ENTRY: u64 = 0xFFFF_FFFF_FFFF_FFFF;

pub struct ReplayProtection {
    most_recent_sequence: u64,
    received_packet: [u64; REPLAY_BUFFER_SIZE],
}

impl Clone for ReplayProtection {
    fn clone(&self) -> Self {
        Self {
            most_recent_sequence: self.most_recent_sequence,
            received_packet: self.received_packet,
        }
    }
}

impl ReplayProtection {
    pub fn new() -> Self {
        Self {
            most_recent_sequence: 0,
            received_packet: [EMPTY_ENTRY; REPLAY_BUFFER_SIZE],
        }
    }

    pub fn packet_already_received(&self, sequence: u64) -> bool {
        if sequence + (REPLAY_BUFFER_SIZE as u64) <= self.most_recent_sequence {
            return true;
        }

        let index = sequence as usize % REPLAY_BUFFER_SIZE;

        if self.received_packet[index] == EMPTY_ENTRY {
            return false;
        }

        if self.received_packet[index] >= sequence {
            return true;
        }

        false
    }

    pub fn advance_sequence(&mut self, sequence: u64) {
        if sequence > self.most_recent_sequence {
            self.most_recent_sequence = sequence;
        }

        let index = sequence as usize % REPLAY_BUFFER_SIZE;

        self.received_packet[index] = sequence;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_replay_protection() {
        for _ in 0..2 {
            let mut replay_protection = ReplayProtection::new();

            assert_eq!(replay_protection.most_recent_sequence, 0);

            // the first time we receive packets, they should not be already received
            const MAX_SEQUENCE: u64 = REPLAY_BUFFER_SIZE as u64 * 4;

            for sequence in 0..MAX_SEQUENCE {
                assert!(!replay_protection.packet_already_received(sequence));
                replay_protection.advance_sequence(sequence);
            }

            // old packets outside buffer should be considered already received
            assert!(replay_protection.packet_already_received(0));

            // packets received a second time should be flagged already received
            for sequence in MAX_SEQUENCE - 10..MAX_SEQUENCE {
                assert!(replay_protection.packet_already_received(sequence));
            }

            // jumping ahead to a much higher sequence should be considered not already received
            assert!(
                !replay_protection.packet_already_received(MAX_SEQUENCE + REPLAY_BUFFER_SIZE as u64)
            );

            // old packets should be considered already received
            for sequence in 0..MAX_SEQUENCE {
                assert!(replay_protection.packet_already_received(sequence));
            }
        }
    }
}
