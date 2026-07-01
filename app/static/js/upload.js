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
        if (e === 'pdf')  return '<i class="fas fa-file-pdf text-danger file-icon"></i>';
        if (e === 'docx') return '<i class="fas fa-file-word text-primary file-icon"></i>';
        if (['png','jpg','jpeg'].includes(e)) return '<i class="fas fa-file-image text-success file-icon"></i>';
        return '<i class="fas fa-file file-icon"></i>';
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

            const badge = valid
                ? `<span class="badge bg-success file-badge">Ready</span>`
                : (!ALLOWED.includes(ext(file.name))
                    ? `<span class="badge bg-danger file-badge">Invalid file type</span>`
                    : `<span class="badge bg-warning text-dark file-badge">Too large</span>`);

            card.innerHTML = `
                ${fileIcon(file.name)}
                <div class="file-info">
                    <div class="file-name" title="${file.name}">${file.name}</div>
                    <div class="file-size">${formatBytes(file.size)}</div>
                </div>
                ${badge}
                <button type="button" class="btn-remove" data-index="${index}" title="Remove">
                    <i class="fas fa-times"></i>
                </button>`;

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
        this.value = '';
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
