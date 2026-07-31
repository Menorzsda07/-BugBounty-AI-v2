from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    openai_api_key: str = ""
    openai_model: str = "gpt-5"
    hackerone_api_username: str = ""
    hackerone_api_token: str = ""
    allow_live_hackerone: bool = False
    app_data_dir: str = "./data"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
