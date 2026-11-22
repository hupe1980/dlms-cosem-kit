```rust
let link = WrapperTransport::connect("10.0.0.5:4059", 0x10, 0x01)?;
let mut meter: Client<_, _> =
    Client::connect(link, ClientConfig::default(), RustCryptoProvider::os(KeyRing::default()))?;

// The value with its scaler and unit, exact: "12345678 Wh".
println!("{}", meter.read_scaled(3, ACTIVE_ENERGY_IMPORT_TOTAL)?);

// A load profile far larger than one APDU, whole — block transfer and
// general block transfer happen inside the call.
let profile = meter.get(AttributeDescriptor::new(7, LOAD_PROFILE, 2))?;
meter.release()?;
```
