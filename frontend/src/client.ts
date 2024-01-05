import { ClientInfo, DecryptRequest, DecryptState, Empty, NetworkName, } from './packets_pb';
import { SniffinsonClient } from './packets_grpc_web_pb';

var client = new SniffinsonClient('http://localhost:8080');

function getNetworks() {
    console.log("Getting all the deteected networks");
    client.getAllAccessPoints(new Empty(), {}, function(err, response) {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        let ssidList = response.getNamesList();
        let networkTable = document.getElementById("networks_list");
        networkTable.innerHTML = ''; // Remove everything that was there prev
        for (const ssid of ssidList) {
            let input = document.createElement("input");
            input.type = "radio";

            let th = document.createElement("th");
            th.textContent = ssid; // look into packets.proto:AP for more info
            th.appendChild(input);
            networkTable.append(th)
        }

        console.log("Got access point list: ", ssidList);
    });
};

function getNetworkByName() {
    console.log("Getting a specific network");
    let networkTable = document.getElementById("networks_list");
    let selectedNetwork = "";
    networkTable.childNodes.forEach((row) => {
        let radio = row.lastChild as HTMLInputElement;
        if (radio.checked) selectedNetwork = row.textContent;
    })

    let request = new NetworkName();
    request.setSsid(selectedNetwork);
    console.log("Sending request for the network: ", selectedNetwork);

    client.getAccessPoint(request, {}, (err, response) => {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        let apName = response.getName();
        let apBssid = response.getBssid();
        let apChannel = response.getChannel();

        let netInfo = document.getElementById("net_info");
        netInfo.innerHTML = "";
        let table = document.createElement('table');

        let clientInfos = response.getClientsList().map((info: ClientInfo) => {
            return `Client ${info.getAddr()} is decrypted: ${info.getIsDecrypted()} and has got ${info.getHandshakeNum()} handshakes`
        })

        for (const elem of [apName, apBssid, apChannel, ...clientInfos]) {
            let row = document.createElement('tr');
            let data = document.createElement('td');
            data.textContent = elem.toString();
            row.appendChild(data)
            table.appendChild(row)
        }

        netInfo.appendChild(table);
    });
}

function tryInputPassword() {
    console.log("Trying to input a password");
    let networkTable = document.getElementById("networks_list");
    let selectedNetwork = ""
    networkTable.childNodes.forEach((row) => {
        let radio = row.lastChild as HTMLInputElement;
        if (radio.checked) selectedNetwork = row.textContent;
    })

    let input = document.getElementById("password_text") as HTMLInputElement;
    let request = new DecryptRequest();
    request.setSsid(selectedNetwork);
    request.setPasswd(input.value.trim());

    console.log("Trying to provide a password for the network", selectedNetwork);
    console.log("With password", input.value.trim());

    client.providePassword(request, {}, (err, response) => {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        switch (response.getState()) {
            case DecryptState.SUCCESS:
                console.log("Success")
                break;
            case DecryptState.WRONG_OR_NO_DATA:
                console.log("The key is wrong or we didn't have 4 handshakes in any client")
                break;
            case DecryptState.ALREADY_DECRYPTED:
                console.log("Already decrypted, idiot")
                break
            case DecryptState.WRONG_NETWORK_NAME:
                console.log("Wrong network name, how did you even manage to do that?")
                break
        }
    })
}

function tryGetStream() {
    console.log("Trying to get the decrypted stream");
    let networkTable = document.getElementById("networks_list");
    let selectedNetwork = ""
    networkTable.childNodes.forEach((row) => {
        let radio = row.lastChild as HTMLInputElement;
        if (radio.checked) selectedNetwork = row.textContent;
    })

    let request = new NetworkName();
    request.setSsid(selectedNetwork);

    let stream = client.getDecryptedPackets(request, {});
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

function ignoreNetwork() {
    console.log("Trying to send a network to ignore")
    let input = document.getElementById("ignore_network_text") as HTMLInputElement;
    let ssid = input.value;

    let request = new NetworkName()
    request.setSsid(ssid);
    client.ignoreNetwork(request, {}, function(err, response) {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        // This doesn't return anythin
    })
}

function getIgnoredNetworks() {
    console.log("Trying get the ignored networks")
    client.getIgnoredNetworks(new Empty(), {}, function(err, response) {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        let ignoredList = document.getElementById("ignored_networks_list");
        ignoredList.innerHTML = '';
        let table = document.createElement("table");
        let ssidList = response.getNamesList();
        for (const ssid of ssidList) {
            let row = document.createElement('tr');
            let data = document.createElement('td');
            data.textContent = ssid;
            row.appendChild(data)
            table.appendChild(row)
        }

        ignoredList.appendChild(table);
    })
}

function deauthNetwork() {
    console.log("Trying to deauth net")
    let networkTable = document.getElementById("networks_list");
    let selectedNetwork = "";
    networkTable.childNodes.forEach((row) => {
        let radio = row.lastChild as HTMLInputElement;
        if (radio.checked) selectedNetwork = row.textContent;
    })

    let request = new NetworkName();
    request.setSsid(selectedNetwork);

    console.log("Sending deauth request for", selectedNetwork);
    client.deauthNetwork(request, {}, (err, response) => {
        if (err) {
            console.error("Got err: ", err)
            return;
        }

        console.log("got resp");
        // This doesn't return anythin
    })
}

document.getElementById('get_networks').addEventListener('click', getNetworks);
document.getElementById('get_ap').addEventListener('click', getNetworkByName);
document.getElementById('put_passwd').addEventListener('click', tryInputPassword);
document.getElementById('get_stream').addEventListener('click', tryGetStream);
document.getElementById('ignore_network').addEventListener('click', ignoreNetwork);
document.getElementById('get_ignored_networks').addEventListener('click', getIgnoredNetworks);
document.getElementById('deauth_network').addEventListener('click', deauthNetwork);
