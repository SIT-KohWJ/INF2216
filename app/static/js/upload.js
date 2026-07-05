// Evidence file upload — only loaded on /submit
document.addEventListener('DOMContentLoaded', function () {
    const input    = document.getElementById('evidenceInput');
    const dropzone = document.getElementById('dropzone');
    const fileList = document.getElementById('file-list');
    const errBox   = document.getElementById('file-error');
    const form     = input ? input.closest('form') : null;

    if (!input || !dropzone) return;

    const ALLOWED = ['pdf', 'docx', 'png', 'jpg', 'jpeg'];
    const MAX_FILES = 5;
    const MAX_BYTES = 10 * 1024 * 1024;

    let selectedFiles = [];

    function ext(name) { return name.split('.').pop().toLowerCase(); }

    function formatBytes(b) {
        if (b < 1024) return b + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        return (b / 1048576).toFixed(1) + ' MB';
    }

    function fileIcon(name) {
        const e = ext(name);
        const icon = document.createElement('i');
        icon.classList.add('file-icon', 'fas');
        if (e === 'pdf') {
            icon.classList.add('fa-file-pdf', 'text-danger');
        } else if (e === 'docx') {
            icon.classList.add('fa-file-word', 'text-primary');
        } else if (['png', 'jpg', 'jpeg'].includes(e)) {
            icon.classList.add('fa-file-image', 'text-success');
        } else {
            icon.classList.add('fa-file');
        }
        return icon;
    }

    function showError(msg) {
        errBox.textContent = msg;
        errBox.classList.remove('d-none');
    }

    function clearError() {
        errBox.textContent = '';
        errBox.classList.add('d-none');
    }

    function syncInput() {
        const dt = new DataTransfer();
        selectedFiles.forEach(f => dt.items.add(f));
        input.files = dt.files;
    }

    function renderList() {
        fileList.innerHTML = '';
        clearError();
        selectedFiles.forEach(function (file, index) {
            const valid = ALLOWED.includes(ext(file.name)) && file.size <= MAX_BYTES;
            const card  = document.createElement('div');
            card.className = 'file-card ' + (valid ? 'valid' : 'invalid');
            card.appendChild(fileIcon(file.name));

            const info = document.createElement('div');
            info.className = 'file-info';

            const nameDiv = document.createElement('div');
            nameDiv.className = 'file-name';
            nameDiv.title = file.name;       // DOM property assignment, not HTML — safe
            nameDiv.textContent = file.name; // safe: not interpreted as markup
            info.appendChild(nameDiv);

            const sizeDiv = document.createElement('div');
            sizeDiv.className = 'file-size';
            sizeDiv.textContent = formatBytes(file.size);
            info.appendChild(sizeDiv);

            card.appendChild(info);

            const badge = document.createElement('span');
            badge.classList.add('badge', 'file-badge');
            if (valid) {
                badge.classList.add('bg-success');
                badge.textContent = 'Ready';
            } else if (!ALLOWED.includes(ext(file.name))) {
                badge.classList.add('bg-danger');
                badge.textContent = 'Invalid file type';
            } else {
                badge.classList.add('bg-warning', 'text-dark');
                badge.textContent = 'Too large';
            }
            card.appendChild(badge);

            const removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'btn-remove';
            removeBtn.dataset.index = index;
            removeBtn.title = 'Remove';
            const removeIcon = document.createElement('i');
            removeIcon.className = 'fas fa-times';
            removeBtn.appendChild(removeIcon);
            card.appendChild(removeBtn);

            fileList.appendChild(card);
        });

        fileList.querySelectorAll('.btn-remove').forEach(function (btn) {
            btn.addEventListener('click', function () {
                selectedFiles.splice(parseInt(this.dataset.index), 1);
                syncInput();
                renderList();
            });
        });
    }

    function addFiles(newFiles) {
        clearError();
        if (selectedFiles.length + Array.from(newFiles).length > MAX_FILES) {
            showError(`You can only attach up to ${MAX_FILES} files. Remove some before adding more.`);
            return;
        }

        const seen = new Set(selectedFiles.map(f => f.name + f.size));
        Array.from(newFiles).forEach(function (f) {
            if (!seen.has(f.name + f.size)) {
                selectedFiles.push(f);
                seen.add(f.name + f.size);
            }
        });

        syncInput();
        renderList();
    }

    dropzone.addEventListener('click', function () { input.click(); });

    dropzone.addEventListener('dragover', function (e) {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });
    dropzone.addEventListener('dragleave', function () {
        dropzone.classList.remove('dragover');
    });
    dropzone.addEventListener('drop', function (e) {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
    });

    input.addEventListener('change', function () {
        if (this.files.length) addFiles(this.files);
    });

    if (form) {
        form.addEventListener('submit', function (e) {
            if (selectedFiles.length > MAX_FILES) {
                e.preventDefault();
                showError(`Too many files — maximum ${MAX_FILES} allowed.`);
                return;
            }
            for (const file of selectedFiles) {
                if (!ALLOWED.includes(ext(file.name))) {
                    e.preventDefault();
                    showError(`"${file.name}" is not an allowed type. Allowed: PDF, DOCX, PNG, JPG`);
                    return;
                }
                if (file.size > MAX_BYTES) {
                    e.preventDefault();
                    showError(`"${file.name}" exceeds the 10MB limit (${formatBytes(file.size)}).`);
                    return;
                }
            }
        });
    }
});

// Live character counters for the title and description fields.
document.addEventListener('DOMContentLoaded', function () {
    function wireCounter(fieldId, counterId, limit) {
        const field = document.getElementById(fieldId);
        const counter = document.getElementById(counterId);
        if (!field || !counter) return;

        function sync() {
            counter.textContent = `${field.value.length} / ${limit}`;
        }

        field.addEventListener('input', sync);
        sync();
    }

    wireCounter('title', 'title-counter', 100);
    wireCounter('description', 'description-counter', 10000);
});
