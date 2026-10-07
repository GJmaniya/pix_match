document.addEventListener('DOMContentLoaded', () => {
    const preview = document.getElementById('watermark-preview');
    const position = document.getElementById('watermark-position');
    const opacity = document.getElementById('watermark-opacity');
    const size = document.getElementById('watermark-size');
    const enabled = document.getElementById('watermark-enabled');

    // ── Preview update ──────────────────────────────────────────────
    const updatePreview = () => {
        if (!preview || !position || !opacity || !size || !enabled) return;

        const primaryLogo = document.getElementById('watermark-preview-logo');
        const secondaryLogo = document.getElementById('watermark-preview-logo-secondary');

        if (primaryLogo) {
            primaryLogo.className = `watermark-preview-logo position-${position.value}`;
            primaryLogo.style.display = enabled.checked ? '' : 'none';
        }
        if (secondaryLogo) {
            secondaryLogo.className = `watermark-preview-logo watermark-preview-logo--secondary position-${position.value}`;
            secondaryLogo.style.display = enabled.checked ? '' : 'none';
        }

        preview.style.setProperty('--preview-opacity', Number(opacity.value) / 100);
        preview.style.setProperty('--preview-size', `${size.value}%`);

        const opacityOutput = document.getElementById('opacity-value');
        const sizeOutput = document.getElementById('size-value');
        if (opacityOutput) opacityOutput.value = `${opacity.value}%`;
        if (sizeOutput) sizeOutput.value = `${size.value}%`;
    };

    [position, opacity, size, enabled].forEach((control) => {
        if (control) control.addEventListener('input', updatePreview);
    });

    // ── Helper: show/hide a remove button ──────────────────────────
    const showRemoveBtn = (btn, visible) => {
        if (!btn) return;
        if (visible) {
            btn.classList.remove('watermark-remove-btn--hidden');
        } else {
            btn.classList.add('watermark-remove-btn--hidden');
        }
    };

    // ── Wire a single logo slot ─────────────────────────────────────
    const wireLogoSlot = ({ fileInputId, labelId, removeBtn, previewImgId, placeholderId }) => {
        const fileInput = document.getElementById(fileInputId);
        const uploadLabel = document.getElementById(labelId);
        const previewImg = document.getElementById(previewImgId);
        const placeholder = placeholderId ? document.getElementById(placeholderId) : null;

        if (fileInput) {
            fileInput.addEventListener('change', () => {
                const file = fileInput.files && fileInput.files[0];
                if (!file) return;

                // Validate size
                if (file.size > 5 * 1024 * 1024) {
                    fileInput.value = '';
                    if (uploadLabel) uploadLabel.textContent = 'File too large (max 5 MB)';
                    return;
                }
                // Validate type
                if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
                    fileInput.value = '';
                    if (uploadLabel) uploadLabel.textContent = 'Use PNG, JPG, or WEBP';
                    return;
                }

                if (uploadLabel) uploadLabel.textContent = file.name;

                if (previewImg) {
                    previewImg.src = URL.createObjectURL(file);
                    previewImg.hidden = false;
                    previewImg.onload = () => URL.revokeObjectURL(previewImg.src);
                }
                if (placeholder) placeholder.hidden = true;

                // Show the remove button now that a file is staged
                showRemoveBtn(removeBtn, true);
            });
        }

        // ── Remove button click ─────────────────────────────────────
        if (removeBtn) {
            removeBtn.addEventListener('click', () => {
                const clearTargetId = removeBtn.dataset.clearTarget;
                const removeFieldId = removeBtn.dataset.removeField;
                const labelTargetId = removeBtn.dataset.labelTarget;
                const labelDefault = removeBtn.dataset.labelDefault || 'Choose a logo';
                const previewTargetId = removeBtn.dataset.previewTarget;
                const placeholderTargetId = removeBtn.dataset.placeholderTarget;

                // Clear file input
                const inputToClear = clearTargetId ? document.getElementById(clearTargetId) : null;
                if (inputToClear) inputToClear.value = '';

                // Set remove hidden field to '1' so server deletes the saved logo
                const removeField = removeFieldId ? document.getElementById(removeFieldId) : null;
                if (removeField) removeField.value = '1';

                // Reset label
                const lbl = labelTargetId ? document.getElementById(labelTargetId) : null;
                if (lbl) lbl.textContent = labelDefault;

                // Hide preview image
                const previewTarget = previewTargetId ? document.getElementById(previewTargetId) : null;
                if (previewTarget) {
                    previewTarget.hidden = true;
                    previewTarget.src = '';
                }

                // Show placeholder for primary only
                const placeholderTarget = placeholderTargetId ? document.getElementById(placeholderTargetId) : null;
                if (placeholderTarget) placeholderTarget.hidden = false;

                // Hide the remove button itself
                showRemoveBtn(removeBtn, false);

                // Submit the form so the server removes the stored logo immediately
                const form = removeBtn.closest('form');
                if (form) form.requestSubmit();
            });
        }
    };

    // ── Register primary slot ───────────────────────────────────────
    wireLogoSlot({
        fileInputId: 'logo-file',
        labelId: 'upload-label',
        removeBtn: document.getElementById('remove-primary-btn'),
        previewImgId: 'watermark-preview-logo',
        placeholderId: 'watermark-preview-placeholder',
    });

    // ── Register secondary slot ─────────────────────────────────────
    wireLogoSlot({
        fileInputId: 'secondary-logo-file',
        labelId: 'upload-label-secondary',
        removeBtn: document.getElementById('remove-secondary-btn'),
        previewImgId: 'watermark-preview-logo-secondary',
        placeholderId: '',
    });

    // ── Sidebar toggle ──────────────────────────────────────────────
    const sidebarToggle = document.getElementById('sidebarToggle');
    const sidebar = document.querySelector('.sidebar');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', () => sidebar.classList.toggle('show'));
    }

    updatePreview();
});

