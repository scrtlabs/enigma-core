use crate::localstd::fmt::{self, Formatter};
use crate::localstd::vec::Vec;
use crate::primitives::km_primitives::*;
use crate::serde::{de::{EnumAccess, Error, IgnoredAny, MapAccess, SeqAccess, Unexpected, VariantAccess, Visitor},
                   ser::SerializeStruct,
                   Deserialize, Deserializer, Serialize, Serializer};
use enigma_types::{ContractAddress, StateKey};
// The main reason why we need to implement Serialize/Deserialize ourselves is because the derive macro
// contains `extern crate serde as _serde` but we renamed serde. so that's invalid. https://github.com/serde-rs/serde/pull/1499
impl Serialize for UserMessage {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut state = Serializer::serialize_struct(ser, "UserMessage", 2)?;
        state.serialize_field("prefix", &self.prefix)?;
        state.serialize_field("pubkey", &self.pubkey)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for UserMessage {
    fn deserialize<D>(des: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct UserMessageVisitor;

        impl<'de> Visitor<'de> for UserMessageVisitor {
            type Value = UserMessage;
            fn expecting(&self, fmt: &mut Formatter) -> fmt::Result { fmt.write_str("struct UserMessage") }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where A: SeqAccess<'de> {
                let err_msg = "struct UserMessage with 2 elements";
                let prefix = seq.next_element::<[u8; 19]>()?.ok_or_else(|| Error::invalid_length(0, &err_msg))?;
                let pubkey = seq.next_element::<Vec<u8>>()?.ok_or_else(|| Error::invalid_length(2, &err_msg))?;
                if pubkey.len() != 64 {
                    return Err(Error::invalid_value(Unexpected::Bytes(&pubkey), &"The pubkey should be 64 bytes"));
                }
                Ok(UserMessage { prefix, pubkey })
            }
        }

        des.deserialize_newtype_struct("UserMessage", UserMessageVisitor)
    }
}

impl Serialize for PrincipalMessageType {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match *self {
            PrincipalMessageType::Response(ref f) => ser.serialize_newtype_variant("PrincipalMessageType", 0, "Response", f),
            PrincipalMessageType::Request(ref f) => ser.serialize_newtype_variant("PrincipalMessageType", 1, "Request", f),
            PrincipalMessageType::EncryptedResponse(ref f) => {
                ser.serialize_newtype_variant("PrincipalMessageType", 2, "EncryptedResponse", f)
            }
        }
    }
}

impl<'de> Deserialize<'de> for PrincipalMessageType {
    #[inline]
    fn deserialize<D>(des: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        enum PrincipalMessageTypeFields {
            Response,
            Request,
            EncryptedResponse,
        }
        struct FieldsVisitor;

        struct PrincipalMessageTypeVisitor;
        const VARIANTS: &[&str] = &["Response", "Request", "EncryptedResponse"];

        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = PrincipalMessageTypeFields;
            fn expecting(&self, fmt: &mut Formatter) -> fmt::Result { fmt.write_str("variant identifier") }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where E: Error {
                match value {
                    "Response" => Ok(PrincipalMessageTypeFields::Response),
                    "Request" => Ok(PrincipalMessageTypeFields::Request),
                    "EncryptedResponse" => Ok(PrincipalMessageTypeFields::EncryptedResponse),
                    _ => Err(Error::unknown_variant(value, VARIANTS)),
                }
            }
        }

        impl<'de> Deserialize<'de> for PrincipalMessageTypeFields {
            #[inline]
            fn deserialize<D>(des: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                des.deserialize_identifier(FieldsVisitor)
            }
        }

        impl<'de> Visitor<'de> for PrincipalMessageTypeVisitor {
            type Value = PrincipalMessageType;
            fn expecting(&self, fmt: &mut Formatter) -> fmt::Result { fmt.write_str("enum PrincipalMessageType") }
            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where A: EnumAccess<'de> {
                match data.variant()? {
                    (PrincipalMessageTypeFields::Response, var) => {
                        var.newtype_variant::<Vec<(ContractAddress, StateKey)>>().map(PrincipalMessageType::Response)
                    }
                    (PrincipalMessageTypeFields::Request, var) => {
                        var.newtype_variant::<Option<Vec<ContractAddress>>>().map(PrincipalMessageType::Request)
                    }
                    (PrincipalMessageTypeFields::EncryptedResponse, var) => {
                        var.newtype_variant::<Vec<u8>>().map(PrincipalMessageType::EncryptedResponse)
                    }
                }
            }
        }

        des.deserialize_enum("PrincipalMessageType", VARIANTS, PrincipalMessageTypeVisitor)
    }
}

impl Serialize for PrincipalMessage {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut state = Serializer::serialize_struct(ser, "PrincipalMessage", 5)?;
        state.serialize_field("prefix", &self.prefix)?;
        state.serialize_field("data", &self.data)?;
        state.serialize_field("pubkey", &self.pubkey)?;
        state.serialize_field("id", &self.id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PrincipalMessage {
    fn deserialize<D>(des: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[allow(non_camel_case_types)]
        enum PrincipalMessageFields {
            prefix,
            data,
            pubkey,
            id,
            __ignore,
        }
        struct FieldsVisitor;
        struct PrincipalMessageVisitor;
        const VARIANTS: &[&str] = &["prefix", "data", "pubkey", "id"];

        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = PrincipalMessageFields;
            fn expecting(&self, fmt: &mut Formatter) -> fmt::Result { fmt.write_str("field identifier") }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where E: Error {
                match value {
                    "prefix" => Ok(PrincipalMessageFields::prefix),
                    "data" => Ok(PrincipalMessageFields::data),
                    "pubkey" => Ok(PrincipalMessageFields::pubkey),
                    "id" => Ok(PrincipalMessageFields::id),
                    _ => Ok(PrincipalMessageFields::__ignore),
                }
            }
        }

        impl<'de> Deserialize<'de> for PrincipalMessageFields {
            #[inline]
            fn deserialize<D>(des: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                des.deserialize_identifier(FieldsVisitor)
            }
        }

        impl<'de> Visitor<'de> for PrincipalMessageVisitor {
            type Value = PrincipalMessage;
            fn expecting(&self, fmt: &mut Formatter) -> fmt::Result { fmt.write_str("struct PrincipalMessage") }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where A: SeqAccess<'de> {
                let err_msg = "struct PrincipalMessage with 4 elements";
                let prefix = seq.next_element::<[u8; 14]>()?.ok_or_else(|| Error::invalid_length(0, &err_msg))?;
                let data = seq.next_element::<PrincipalMessageType>()?.ok_or_else(|| Error::invalid_length(1, &err_msg))?;
                let pubkey = seq.next_element::<Vec<u8>>()?.ok_or_else(|| Error::invalid_length(2, &err_msg))?;
                if pubkey.len() != 64 {
                    return Err(Error::invalid_value(Unexpected::Bytes(&pubkey), &"The pubkey should be 64 bytes"));
                }
                let id = seq.next_element::<MsgID>()?.ok_or_else(|| Error::invalid_length(3, &err_msg))?;

                Ok(PrincipalMessage { prefix, data, pubkey, id })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where A: MapAccess<'de> {
                let mut prefix: Option<[u8; 14]> = None;
                let mut data: Option<PrincipalMessageType> = None;
                let mut pubkey: Option<Vec<u8>> = None;
                let mut id: Option<MsgID> = None;

                while let Some(key) = map.next_key::<PrincipalMessageFields>()? {
                    match key {
                        PrincipalMessageFields::prefix => {
                            if prefix.is_some() {
                                return Err(<A::Error as Error>::duplicate_field("prefix"));
                            } else {
                                prefix = Some(map.next_value()?);
                            }
                        }
                        PrincipalMessageFields::data => {
                            if data.is_some() {
                                return Err(<A::Error as Error>::duplicate_field("data"));
                            } else {
                                data = Some(map.next_value()?);
                            }
                        }
                        PrincipalMessageFields::pubkey => {
                            if pubkey.is_some() {
                                return Err(<A::Error as Error>::duplicate_field("pubkey"));
                            } else {
                                pubkey = Some(map.next_value()?);
                            }
                        }
                        PrincipalMessageFields::id => {
                            if id.is_some() {
                                return Err(<A::Error as Error>::duplicate_field("id"));
                            } else {
                                id = Some(map.next_value()?);
                            }
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }

                let prefix = prefix.ok_or_else(|| Error::missing_field("prefix"))?;
                let data = data.ok_or_else(|| Error::missing_field("data"))?;
                let pubkey = pubkey.ok_or_else(|| Error::missing_field("pubkey"))?;
                let id = id.ok_or_else(|| Error::missing_field("id"))?;

                Ok(PrincipalMessage { prefix, data, pubkey, id })
            }
        }

        des.deserialize_struct("PrincipalMessage", VARIANTS, PrincipalMessageVisitor)
    }
}
