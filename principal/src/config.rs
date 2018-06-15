use std::collections::HashMap;
fn read_config() -> HashMap<String, String>
{
    let mut settings = config::Config::default();
    settings
        // Add in `./Settings.toml`
        .merge(config::File::with_name("Config")).unwrap()
        // Add in settings from the environment (with a prefix of APP)
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .merge(config::Environment::with_prefix("APP")).unwrap();

    let app_config = settings.try_into::<HashMap<String, String>>().unwrap();

    app_config.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file_is_readable() {
        let app_config = read_config();
        let key = String::from("enigma_path1");
        let filename = app_config.get(&key).unwrap();
        assert!(filename);
    }
}
