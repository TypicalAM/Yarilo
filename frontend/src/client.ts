import { ClientInfo, DeauthRequest, DecryptRequest, DecryptState, Empty, File, NetworkName } from './packets_pb';
import { SniffinsonClient } from './packets_grpc_web_pb';

var client = new SniffinsonClient('http://localhost:8080');

const logBoxContainer = document.getElementById('logBoxContainer');
const logBox = document.getElementById('logBox');
const messageWindow = document.getElementById('messageWindow');

function getSelectedNetwork(): string {
    let networkTable = document.getElementById('networks_list').firstChild;
    let selectedNetwork = '';
    networkTable.childNodes.forEach((row) => {
        let radio = row.lastChild.lastChild as HTMLInputElement; // <tr> <td> text <input>
        if (radio.checked) selectedNetwork = row.textContent;
    });
    return selectedNetwork;
}

function getSelectedRecording(): string {
    let fileTable = document.getElementById('files_list').firstChild;
    let selectedFile = '';
    fileTable.childNodes.forEach((row) => {
        let radio = row.lastChild.lastChild as HTMLInputElement; // <tr> <td> text <input>
        if (radio.checked) selectedFile = row.textContent;
    });
    return selectedFile;
}

function getNetworks() {
    console.log('Getting all the detected networks');
    client.getAllAccessPoints(new Empty(), {}, function (err, response) {
        if (err) {
            console.error('Got err: ', err);
            return;
        }

        let ssidList = response.getNamesList();
        let networkTable = document.getElementById('networks_list');
        networkTable.innerHTML = ''; // Remove everything that was there prev
        let table = document.createElement('table');
        for (const ssid of ssidList) {
            let row = document.createElement('tr');
            let data = document.createElement('td');
            data.textContent = ssid;

            let input = document.createElement('input');
            input.type = 'radio';
            data.append(input);
            row.appendChild(data);
            table.appendChild(row);
        }

        networkTable.appendChild(table);
        console.log('Got access point list: ', ssidList);
    });
}

function getNetworkByName() {
    console.log('Getting a specific network');
    let selectedNetwork = getSelectedNetwork();
    let request = new NetworkName();
    request.setSsid(selectedNetwork);
    console.log('Sending request for the network: ', selectedNetwork);

    client.getAccessPoint(request, {}, (err, response) => {
        if (err) {
            console.error('Got err: ', err);
            return;
        }

        let netInfo = document.getElementById('net_info');
        netInfo.innerHTML = '';
        let table = document.createElement('table');

        let clientInfos = response.getClientsList().map((info: ClientInfo) => {
            return `Client ${info.getAddr()} is decrypted: ${info.getIsDecrypted()} and has got ${info.getHandshakeNum()} handshakes`;
        });

        let apinfo = `Name: ${response.getName()}, BSSID: ${response.getBssid()}, Channel: ${response.getChannel()}, Got ${response.getEncryptedPacketCount()} encrypted and ${response.getDecryptedPacketCount()} decrypted packets`;
        for (const elem of [apinfo, ...clientInfos]) {
            let row = document.createElement('tr');
            let data = document.createElement('td');
            data.textContent = elem.toString();
            row.appendChild(data);
            table.appendChild(row);
        }

        netInfo.appendChild(table);
    });
}

function tryInputPassword() {
    console.log('Trying to input a password');
    let selectedNetwork = getSelectedNetwork();
    let input = document.getElementById('password_text') as HTMLInputElement;
    let request = new DecryptRequest();
    request.setSsid(selectedNetwork);
    request.setPasswd(input.value.trim());

    console.log('Trying to provide a password for the network', selectedNetwork);
    console.log('With password', input.value.trim());

    client.providePassword(request, {}, (err, response) => {
        if (err) {
            console.error('Got err: ', err);
            return;
        }

        switch (response.getState()) {
            case DecryptState.SUCCESS:
                console.log('Success');
                break;
            case DecryptState.WRONG_OR_NO_DATA:
                console.log("The key is wrong or we didn't have 4 handshakes in any client");
                break;
            case DecryptState.ALREADY_DECRYPTED:
                console.log('Already decrypted, idiot');
                break;
            case DecryptState.WRONG_NETWORK_NAME:
                console.log('Wrong network name, how did you even manage to do that?');
                break;
        }
    });
}

function tryGetStream() {
    console.log('Trying to get the decrypted stream');
    let selectedNetwork = getSelectedNetwork();
    let request = new NetworkName();
    request.setSsid(selectedNetwork);

    let stream = client.getDecryptedPackets(request, {});

    logBox.innerHTML = '';

    stream.on('data', (response) => {
        let from = response.getFrom();
        let to = response.getTo();
        let logMessage = `${response.getProtocol()} from ${from.getMacaddress()}, ${from.getIpv4address()}, ${from.getPort()} to ${to.getMacaddress()}, ${to.getIpv4address()}, ${to.getPort()}`;

        logBox.innerHTML += `<p>${logMessage}</p>`;
        console.log(logMessage);
    });

    stream.on('end', () => {
        console.log('end');
    });

    let cancelBtn = document.getElementById('cancel_stream');
    cancelBtn.className = 'btn btn-warning';
    cancelBtn.addEventListener('click', () => {
        console.log('Cancelling stream');
        stream.cancel();
        console.log('Stream cancelled');
        cancelBtn.className = 'btn btn-primary';
    });

    logBoxContainer.scrollTop = logBoxContainer.scrollHeight;
}

function ignoreNetwork() {
    console.log('Trying to send a network to ignore');
    let input = document.getElementById('ignore_network_text') as HTMLInputElement;
    let ssid = input.value;

    let request = new NetworkName();
    request.setSsid(ssid);
    client.ignoreNetwork(request, {}, function (err, response) {
        if (err) {
            console.error('Got err: ', err);
            return;
        }

        // This doesn't return anything
    });
}

function getIgnoredNetworks() {
    console.log('Trying get the ignored networks');
    client.getIgnoredNetworks(new Empty(), {}, function (err, response) {
        if (err) {
            console.error('Got err: ', err);
            return;
        }

        let ignoredList = document.getElementById('ignored_networks_list');
        ignoredList.innerHTML = '';
        let table = document.createElement('table');
        let ssidList = response.getNamesList();
        for (const ssid of ssidList) {
            let row = document.createElement('tr');
            let data = document.createElement('td');
            data.textContent = ssid;
            row.appendChild(data);
            table.appendChild(row);
        }

        ignoredList.appendChild(table);
    });
}

function deauthNetwork() {
    console.log('Trying to deauth net');
    let selectedNetwork = getSelectedNetwork();
    let request = new NetworkName();
    request.setSsid(selectedNetwork);

    console.log('Sending deauth request for', selectedNetwork);
    client.deauthNetwork(request, {}, (err, response) => {
        if (err) {
            console.error('Got err: ', err);
            return;
        }

        console.log('got resp');
        // This doesn't return anything
    });
}

function focusNetwork() {
    let selectedNetwork = getSelectedNetwork();
    let request = new NetworkName();
    request.setSsid(selectedNetwork);

    console.log("Sending focus request for", selectedNetwork);
    client.focusNetwork(request, {}, (err, response) => {
        if (err) {
            console.error("Got err: ", err)
            return;
        }
        // This doesn't return anythin
    })
}

function getFocusState() {
    console.log("Sending get focus request");
    client.getFocusState(new Empty(), {}, (err, response) => {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        if (response.getFocused()) {
            console.log("Focus state, focusing network: ", response.getName().getSsid());
        } else {
            console.log("Focus state, not focusing anything")
        }
    })
}

function unfocusNetwork() {
    console.log("Sending stop focus request");
    client.stopFocus(new Empty(), {}, (err, response) => {
        if (err) {
            console.error("Got err: ", err)
            return;
        }
        // This doesn't return anythin
    })
}

function getRecordings() {
    console.log("Getting all the recordings");
    client.getAvailableRecordings(new Empty(), {}, function(err, response) {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        let fileList = response.getFilesList();
        let fileTable = document.getElementById("files_list");
        fileTable.innerHTML = ''; // Remove everything that was there prev
        let table = document.createElement('table');
        for (const filename of fileList) {
            let row = document.createElement('tr');
            let data = document.createElement('td');
            data.textContent = filename.getName();

            let input = document.createElement("input");
            input.type = "radio";
            data.append(input)
            row.appendChild(data)
            table.appendChild(row)
        }

        fileTable.appendChild(table);
        console.log("Got recording file list: ", fileList);
    })
}

function getStreamFromRecording() {
    let filename = getSelectedRecording();

    let request = new File();
    request.setName(filename)

    let stream = client.loadRecording(request, {});
    stream.on('data', (response) => {
        let from = response.getFrom();
        let to = response.getTo();
        console.log(response.getProtocol(), "from", from.getMacaddress(), from.getIpv4address(), from.getPort(), "to", to.getMacaddress(), to.getIpv4address(), to.getPort());
    })

    stream.on('end', () => {
        console.log("end");
    });

    let cancelBtn = document.getElementById('cancel_stream')
    cancelBtn.className = "btn btn-warning";
    cancelBtn.addEventListener('click', () => {
        console.log("Cancelling stream")
        stream.cancel()
        console.log("Stream cancelled")
        cancelBtn.className = "btn btn-primary";
    })
}
function saveStream() {
    console.log("Saving stream...");
    let network = getSelectedNetwork();
    let request = new NetworkName();
    request.setSsid(network);

    client.saveDecryptedTraffic(request, {}, function(err, response) {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        console.log("got resp")
        // empty resp
    })
}

document.getElementById('get_networks').addEventListener('click', getNetworks);
document.getElementById('get_ap').addEventListener('click', getNetworkByName);
document.getElementById('put_passwd').addEventListener('click', tryInputPassword);
document.getElementById('get_stream').addEventListener('click', tryGetStream);
document.getElementById('ignore_network').addEventListener('click', ignoreNetwork);
document.getElementById('get_ignored_networks').addEventListener('click', getIgnoredNetworks);
document.getElementById('deauth_network').addEventListener('click', deauthNetwork);
document.getElementById('focus_network').addEventListener('click', focusNetwork);
document.getElementById('get_focus_state').addEventListener('click', getFocusState);
document.getElementById('unfocus_network').addEventListener('click', unfocusNetwork);
document.getElementById('get_files').addEventListener('click', getRecordings);
document.getElementById('get_stream_recording').addEventListener('click', getStreamFromRecording);
document.getElementById('save_stream').addEventListener('click', saveStream);