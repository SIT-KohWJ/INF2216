import magic
import bleach

ALLOWED_MIME_TYPES = {
    'pdf': 'application/pdf',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg'
}


class FileValidator:
    @staticmethod
    def validate_file_type(file_content, allowed_extensions=None):
        try:
            mime = magic.from_buffer(file_content[:2048], mime=True)
            for ext in (allowed_extensions or ALLOWED_MIME_TYPES.keys()):
                if mime == ALLOWED_MIME_TYPES.get(ext):
                    return True
            return False
        except Exception:
            return False


class InputValidator:
    @staticmethod
    def sanitize_html(text):
        return bleach.clean(text, tags=[], attributes={}, strip=True)
