#[allow(dead_code)] 
pub trait State { 
    fn increment(&mut self, id: &String, key: String, duration: u64) -> u64;
}
