mod ffistr;
mod loader;

fn main() {
    let mut ldr = loader::Loader::new();
    ldr.load_elf("test.elf");
}
