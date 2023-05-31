use mongodb::{options::ClientOptions, bson::{doc, Document}, Client, Database, Collection};
use std::env;

pub struct MyDatabase {
    client: Client,
    database: Database,
}

impl MyDatabase {
    pub async fn new() -> Result<Self, mongodb::error::Error> {
        let database_url = env::var("MONGODB_URI").expect("MONGODB_URI not found in environment variables");

        let client_options = ClientOptions::parse(&database_url).await?;
        let client = Client::with_options(client_options)?;

        let database_name = env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE not found in environment variables");
        let database = client.database(&database_name);

        Ok(Self { client, database })
    }

    pub fn get_collection(&self, collection_name: &str) -> Collection<Document> {
        self.database.collection(collection_name)
    }

    pub async fn insert(&self, collection_name: &str, document: Document) -> Result<(), mongodb::error::Error> {
        let collection = self.get_collection(collection_name);
        collection.insert_one(document, None).await?;
        Ok(())
    }

    pub async fn find(&self, collection_name: &str, query: Document) -> Result<Option<Document>, mongodb::error::Error> {
        let collection = self.get_collection(collection_name);
        let result = collection.find_one(query, None).await?;
        Ok(result)
    }

    pub async fn delete(&self, collection_name: &str, query: Document) -> Result<(), mongodb::error::Error> {
        let collection = self.get_collection(collection_name);
        collection.delete_one(query, None).await?;
        Ok(())
    }
}
