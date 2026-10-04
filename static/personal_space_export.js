// ====== Note Export Logic ======
(function () {
    let exportNoteId = null;

    function getIsPremium() {
        return Boolean(window.EW_CONFIG && window.EW_CONFIG.isPremium);
    }

    // Open export modal
    document.body.addEventListener('click', function (e) {
        const btn = e.target.closest('.export-note-btn');
        if (!btn) return;
        exportNoteId = btn.dataset.id;
        const modal = document.getElementById('export-note-modal');
        if (modal) modal.style.display = 'flex';
    });

    window.closeExportModal = function () {
        const modal = document.getElementById('export-note-modal');
        if (modal) modal.style.display = 'none';
        exportNoteId = null;
    };

    window.exportNote = function (format) {
        if (!exportNoteId) return;

        // Premium gate for DOCX
        if (format === 'docx' && !getIsPremium()) {
            if (window.showCustomAlert) {
                window.showCustomAlert('DOCX export is a Premium feature. Upgrade to unlock formatted exports.', 'warning');
            } else {
                alert('DOCX export is a Premium feature.');
            }
            return;
        }

        // Get the note content from the DOM
        const noteCard = document.querySelector(`.note-card[data-note-id="${exportNoteId}"], .locked-note-card[data-note-id="${exportNoteId}"]`);
        if (!noteCard) return;

        const rawEl = noteCard.querySelector('.rendered-note');
        if (!rawEl) return;
        if (rawEl.hasAttribute('data-lazy')) {
            if (window.showCustomAlert) {
                window.showCustomAlert('This note is still loading. Please wait a moment and try again.', 'warning');
            } else {
                alert('This note is still loading. Please wait a moment and try again.');
            }
            return;
        }
        const rawContent = rawEl.dataset.raw || '';
        const renderedContent = rawEl.innerHTML || '';
        if (!rawContent.trim()) {
            if (window.showCustomAlert) {
                window.showCustomAlert('Unable to export this note — no content available.', 'warning');
            } else {
                alert('Unable to export this note — no content available.');
            }
            return;
        }
        const noteRef = noteCard.querySelector('.note-ref-display');
        const reference = noteRef ? noteRef.textContent.trim() : '';

        // Generate a filename from first line of content
        const firstLine = rawContent.split('\n')[0].replace(/[#*_\[\]()]/g, '').trim().substring(0, 40) || 'note';
        const safeName = firstLine.replace(/[^a-zA-Z0-9 ]/g, '').replace(/\s+/g, '_') || 'note';

        if (format === 'txt') {
            exportAsTxt(rawContent, reference, safeName);
        } else if (format === 'docx') {
            exportAsDocx(rawContent, renderedContent, reference, safeName);
        }

        closeExportModal();
    };

    function exportAsTxt(content, reference, filename) {
        let text = content;
        if (reference) text = reference + '\n\n' + text;
        text += '\n\n---\nExported from EchoWithin';

        const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
        downloadBlob(blob, filename + '.txt');
    }

    function exportAsDocx(rawContent, html, reference, filename) {
        // Build a simple HTML-based DOCX (using HTML-in-DOCX trick)
        let docHtml = '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">';
        docHtml += '<head><meta charset="utf-8"><style>body{font-family:Calibri,sans-serif;font-size:11pt;line-height:1.5;color:#333;}h1{font-size:18pt;}h2{font-size:14pt;}h3{font-size:12pt;}code{background:#f5f5f5;padding:2px 4px;font-family:Consolas,monospace;font-size:10pt;}pre{background:#f5f5f5;padding:10px;font-family:Consolas,monospace;font-size:10pt;}</style></head><body>';
        if (reference) {
            docHtml += '<p style="color:#666;font-size:9pt;border-bottom:1px solid #eee;padding-bottom:6px;">' + escapeHtml(reference) + '</p>';
        }
        docHtml += html;
        docHtml += '<p style="margin-top:20px;border-top:1px solid #eee;padding-top:8px;font-size:8pt;color:#aaa;text-align:center;">Exported from EchoWithin</p>';
        docHtml += '</body></html>';

        const blob = new Blob(['\ufeff' + docHtml], { type: 'application/msword' });
        downloadBlob(blob, filename + '.doc');
    }

    function escapeHtml(str) {
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        setTimeout(function () {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
    }
})();
