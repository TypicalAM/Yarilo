import { ClientInfo, DeauthRequest, DecryptRequest, DecryptState, Empty, File, NetworkName, Packet } from './packets_pb';
import { SniffinsonClient } from './packets_grpc_web_pb';
import { ClientReadableStream } from 'grpc-web';

var client = new SniffinsonClient('http://localhost:8080');

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
        if (radio.checked) selectedFile = radio.innerHTML;
    });
    return selectedFile;
}

function getNetworks() {
    console.log('Getting all the detected networks');
    client.getAllAccessPoints(new Empty(), {}, function(err, response) {
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
            input.name = 'network';
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

        let logMessage = `SSID: ${response.getName()}, BSSID: ${response.getBssid()}, Channel: ${response.getChannel()}`
        netInfo.innerHTML += `<p>${logMessage}</p>`;

        logMessage = `Got ${response.getEncryptedPacketCount()} encrypted and ${response.getDecryptedPacketCount()} decrypted packets`
        netInfo.innerHTML += `<p> ${logMessage}</p>`;

        let clientInfos = response.getClientsList().map((info: ClientInfo) => {
            return `Client ${info.getAddr()} is decrypted: ${info.getIsDecrypted()} and has got ${info.getHandshakeNum()} handshakes`;
        });

        for (const client of clientInfos)
            netInfo.innerHTML += `<p> ${client}</p>`;
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

        let btn = document.getElementById("try_input_password");
        switch (response.getState()) {
            case DecryptState.SUCCESS:
                btn.className = "btn btn-success";
                console.log('Success');
                break;
            case DecryptState.WRONG_OR_NO_DATA:
                btn.className = "btn btn-danger";
                console.log("The key is wrong or we didn't have 4 handshakes in any client");
                break;
            case DecryptState.ALREADY_DECRYPTED:
                btn.className = "btn btn-info";
                console.log('Already decrypted, idiot');
                break;
            case DecryptState.WRONG_NETWORK_NAME:
                console.log('Wrong network name, how did you even manage to do that?');
                break;
        }
    });
}

function streamToColumns(stream: ClientReadableStream<Packet>) {
    const dataBody = document.getElementById('dataBody');

    stream.on('data', (response) => {
        let from = response.getFrom();
        let to = response.getTo();

        let typeContent = response.getProtocol();
        let fromContent = `${from.getMacaddress()} - ${from.getIpv4address()}:${from.getPort()}`;
        let ipPortContent = `${from.getIpv4address()}:${from.getPort()}`;
        let toContent = to.getMacaddress();
        let toIpPortContent = `${to.getIpv4address()}:${to.getPort()}`;

        // Append new row to the table
        dataBody.innerHTML += `<tr>
            <td>${typeContent}</td>
            <td>${fromContent}</td>
            <td>${ipPortContent}</td>
            <td>${toContent}</td>
            <td>${toIpPortContent}</td>
        </tr>`;

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
}

function tryGetStream() {
    console.log('Trying to get the decrypted stream');
    let selectedNetwork = getSelectedNetwork();
    let request = new NetworkName();
    request.setSsid(selectedNetwork);

    streamToColumns(client.getDecryptedPackets(request, {}));
}

function ignoreNetwork() {
    console.log('Trying to send a network to ignore');
    let input = document.getElementById('ignore_network_text') as HTMLInputElement;
    let ssid = input.value;

    let request = new NetworkName();
    request.setSsid(ssid);
    client.ignoreNetwork(request, {}, function(err, _) {
        if (err) {
            console.error('Got err: ', err);
            return;
        }

        // This doesn't return anything
    });
}

function getIgnoredNetworks() {
    console.log('Trying get the ignored networks');
    client.getIgnoredNetworks(new Empty(), {}, function(err, response) {
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

    let network = new NetworkName();
    network.setSsid(selectedNetwork);

    let request = new DeauthRequest()
    request.setNetwork(network)
    let macAddr = "ff:ff:ff:ff:ff:ff";
    request.setUserAddr(macAddr); // TODO: Change this from broadcast to a specific client 

    console.log('Sending deauth request for', selectedNetwork);
    client.deauthNetwork(request, {}, (err, _) => {
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
    client.focusNetwork(request, {}, (err, _) => {
        let focusBtn = document.getElementById("focus_network");
        if (err) {
            console.error("Got err: ", err);
            focusBtn.className = "btn btn-danger"; // Set to error style
            return;
        }

        console.log("Focus state, focusing network: ", selectedNetwork);
        focusBtn.className = "btn btn-success"; // Set to success style
    });
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
    client.stopFocus(new Empty(), {}, (err, _) => {
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
        fileTable.style.whiteSpace = "nowrap"; // inline css love it
        fileTable.style.overflow = "hidden";
        fileTable.style.textOverflow = "ellipsis";
        fileTable.style.width = "200px";

        fileTable.innerHTML = ''; // Remove everything that was there prev
        let table = document.createElement('table');
        for (const filename of fileList) {
            let row = document.createElement('tr');
            let data = document.createElement('td');
            data.textContent += filename.getName().split("-")[0].split(" ").map((name) => { return name[0] }); // only first chars on net
            data.textContent += filename.getName().slice(filename.getName().indexOf('-') + 1).trim()
            let input = document.createElement("input");
            input.type = "radio";
            input.innerHTML = filename.getName();
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
    console.log("Tring to get the recording for", filename)

    let request = new File();
    request.setName(filename)

    streamToColumns(client.loadRecording(request, {}))
}

function saveStream() {
    console.log("Saving stream...");
    let network = getSelectedNetwork();
    let request = new NetworkName();
    request.setSsid(network);

    client.saveDecryptedTraffic(request, {}, function(err, _) {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        console.log("got resp")
        // empty resp
    })
}
let scrollEnabled = false;
function toggleScroll() {
    scrollEnabled = !scrollEnabled;
    const scrollButton = document.getElementById('scrollButton');

    if (scrollEnabled) {
        scrollButton.className = 'btn btn-success'; // Change to green when ON
        scrollDataTable();
    } else {
        scrollButton.className = 'btn btn-danger'; // Change to red when OFF
    }
}

function scrollDataTable() {
    if (scrollEnabled) {
        const dataTable = document.getElementById('dataTable');
        if (dataTable.scrollHeight > 0) {
            // Scroll to the bottom of the table
            dataTable.scrollTop = dataTable.scrollHeight;
        }
        console.log("scroll on (at least trying)")
        // Schedule the next scroll if still enabled
        setTimeout(scrollDataTable, 500);
    }
}

function clearOutput() {
    const dataBody = document.getElementById('dataBody');
    dataBody.innerHTML = ''; // Clear the content of the tbody
}

document.getElementById('get_networks').addEventListener('click', getNetworks);
document.getElementById('get_ap').addEventListener('click', getNetworkByName);
document.getElementById('try_input_password').addEventListener('click', tryInputPassword);
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
document.getElementById('scrollButton').addEventListener('click', toggleScroll);
document.getElementById('clear_output').addEventListener('click', clearOutput);
