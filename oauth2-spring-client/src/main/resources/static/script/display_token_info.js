function createRow(headerData, data) {
    var trElem = document.createElement('tr');
    trElem.classList.add('row', 'data');

    trElem.appendChild(createCell(headerData, 'th'));
    trElem.appendChild(createCell(data, 'td'));

    return trElem;
}

function createCell(innerHtml, cellType) {
    var tdElem = document.createElement(cellType);
    // tdElem.classList.add('cell', clazz);
    tdElem.innerHTML = innerHtml;
    return tdElem;
}

function renderUserInfo(userInfo) {
    var existingTableElem = document.getElementById('userInfoTable');
    var newTableElem = document.createElement('table');
    newTableElem.id = 'userInfoTable';
    newTableElem.classList.add('userInfoTable');


    newTableElem.appendChild(createRow('Login', userInfo.login));
    newTableElem.appendChild(createRow('Id', userInfo.id));
    newTableElem.appendChild(createRow('Node_id', userInfo.node_id));
    newTableElem.appendChild(createRow('Avatar_url', userInfo.avatar_url));
    newTableElem.appendChild(createRow('Gravatar_id', userInfo.gravatar_id));
    newTableElem.appendChild(createRow('Url', userInfo.url));
    newTableElem.appendChild(createRow('Html_url', userInfo.html_url));
    newTableElem.appendChild(createRow('Followers_url', userInfo.followers_url));
    newTableElem.appendChild(createRow('Following_url', userInfo.following_url));
    newTableElem.appendChild(createRow('Gists_url', userInfo.gists_url));
    newTableElem.appendChild(createRow('Starred_url', userInfo.starred_url));
    newTableElem.appendChild(createRow('Subscriptions_url', userInfo.subscriptions_url));
    newTableElem.appendChild(createRow('Organizations_url', userInfo.organizations_url));
    newTableElem.appendChild(createRow('Repos_url', userInfo.repos_url));
    newTableElem.appendChild(createRow('Events_url', userInfo.events_url));
    newTableElem.appendChild(createRow('Received_events_url', userInfo.received_events_url));
    newTableElem.appendChild(createRow('Type', userInfo.type));
    newTableElem.appendChild(createRow('Site_admin', userInfo.site_admin));
    newTableElem.appendChild(createRow('Name', userInfo.name));
    newTableElem.appendChild(createRow('Company', userInfo.company));
    newTableElem.appendChild(createRow('Blog', userInfo.blog));
    newTableElem.appendChild(createRow('Location', userInfo.location));
    newTableElem.appendChild(createRow('Email', userInfo.email));
    newTableElem.appendChild(createRow('Hireable', userInfo.hireable));
    newTableElem.appendChild(createRow('Bio', userInfo.bio));
    newTableElem.appendChild(createRow('Public_repos', userInfo.public_repos));
    newTableElem.appendChild(createRow('Public_gists', userInfo.public_gists));
    newTableElem.appendChild(createRow('Followers', userInfo.followers));
    newTableElem.appendChild(createRow('Following', userInfo.following));
    newTableElem.appendChild(createRow('Created_at', userInfo.created_at));
    newTableElem.appendChild(createRow('Updated_at', userInfo.updated_at));

    if (existingTableElem) {
        existingTableElem.parentNode.removeChild(existingTableElem);
    }
    document.body.appendChild(newTableElem);
}

function retrieveAndRender() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/user');
    xhr.onload = function () {
        if (xhr.status === 200) {
            try {
                var tokenInfoListe = JSON.parse(xhr.response);
                renderUserInfo(tokenInfoListe);
            } catch (e) {
                console.log("Feil ved parsing/rendering av resultat fra tjenestekall");
            }
        } else {
            console.log("Forventet HTTP 200, fikk " + xhr.status);
        }
    };
    xhr.onerror = function () {
        console.log("Ukjent feil ved kall til tjeneste");
    };
    xhr.send();

    var xhrData = new XMLHttpRequest();
    xhrData.open('GET', '/data');
    xhrData.onload = function () {
        if (xhrData.status === 200) {
            try {
                document.getElementById('userInfoTable').appendChild(createRow('Backend data', xhrData.response))
            } catch (e) {
                console.log("Feil ved parsing/rendering av resultat fra tjenestekall");
            }
        } else {
            console.log("Forventet HTTP 200, fikk " + xhrData.status);
        }
    };
    xhrData.onerror = function () {
        console.log("Ukjent feil ved kall til tjeneste");
    };
    xhrData.send();
}

retrieveAndRender(); // Hent initielle data
