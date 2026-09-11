from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    AI_CREDITS_KEY:str = ""
    SAFE_BROWSING_API_KEY: str = ""
    VIRUS_TOTAL_API_KEY: str = ""
    model_config = SettingsConfigDict(
        env_file='.env',
        extra='ignore',
        env_file_encoding='utf-8'
    )

settings = Settings()

def get_safe_browsing_key():
    return settings.SAFE_BROWSING_API_KEY

def get_virus_total_key():
    return settings.VIRUS_TOTAL_API_KEY

def get_ai_credits_key():
    return settings.AI_CREDITS_KEY