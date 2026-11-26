```rust
let link = WrapperTransport::connect("10.0.0.5:4059", 0x10, 0x01)?;
let mut meter: Client<_, _> =
    Client::connect(link, ClientConfig::default(), RustCryptoProvider::os(KeyRing::default()))?;

println!("{}", meter.read_scaled(3, ACTIVE_ENERGY_IMPORT_TOTAL)?);

let mut storage = [0u8; 4096];
let buffer = AttributeDescriptor::new(7, LOAD_PROFILE, 2);
let value = meter.get_into(buffer, None, &mut storage)?;
println!("{} rows", ProfileBuffer::new(&value)?.len());
meter.release()?;
```
