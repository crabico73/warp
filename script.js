const editor = document.getElementById('editor');
const saveBtn = document.getElementById('saveBtn');
const loadBtn = document.getElementById('loadBtn');

saveBtn.addEventListener('click', () => {
    const content = editor.value;
    localStorage.setItem('textEditorContent', content);
    alert('Content saved!');
});

loadBtn.addEventListener('click', () => {
    const content = localStorage.getItem('textEditorContent');
    if (content) {
        editor.value = content;
        alert('Content loaded!');
    } else {
        alert('No saved content found.');
    }
});
