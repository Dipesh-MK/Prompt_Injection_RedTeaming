import sys
from config import settings
print(f"DEFAULT_VICTIM_MODEL: {getattr(settings, 'DEFAULT_VICTIM_MODEL', 'MISSING')}")
print(f"Directory: {dir(settings)}")
import main
print("Main imported successfully")
