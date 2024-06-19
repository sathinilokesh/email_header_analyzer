function processFile() {
    const fileInput = document.getElementById('emailFile');
    const file = fileInput.files[0];

    if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            const content = e.target.result;
            console.log('File content:', content); // Debug: log file content
            const headers = extractHeaders(content);
            console.log('Extracted headers:', headers); // Debug: log extracted headers
            displayHeaders(headers);
        };
        reader.readAsText(file);
    } else {
        alert("Please select an email file.");
    }
}

function extractHeaders(content) {
    const headers = {};
    const headerEndIndex = content.indexOf("\n\n");

    if (headerEndIndex !== -1) {
        const headerLines = content.substring(0, headerEndIndex).split("\n");

        headerLines.forEach(line => {
            const index = line.indexOf(":");
            if (index !== -1) {
                const key = line.substring(0, index).trim();
                const value = line.substring(index + 1).trim();
                headers[key] = value;
            }
        });
    }

    return headers;
}

function displayHeaders(headers) {
    const headerInfoDiv = document.getElementById('headerInfo');
    headerInfoDiv.innerHTML = '';

    console.log('Displaying headers on the page:', headers); // Debug: log headers before display

    for (const [key, value] of Object.entries(headers)) {
        const headerItem = document.createElement('div');
        headerItem.className = 'header-item';

        const headerLabel = document.createElement('span');
        headerLabel.className = 'header-label';
        headerLabel.textContent = key + ': ';

        const headerValue = document.createElement('span');
        headerValue.className = 'header-value';
        headerValue.textContent = value;

        headerItem.appendChild(headerLabel);
        headerItem.appendChild(headerValue);
        headerInfoDiv.appendChild(headerItem);
    }
}
