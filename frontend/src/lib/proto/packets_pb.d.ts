import * as jspb from 'google-protobuf'



export class Empty extends jspb.Message {
  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Empty.AsObject;
  static toObject(includeInstance: boolean, msg: Empty): Empty.AsObject;
  static serializeBinaryToWriter(message: Empty, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Empty;
  static deserializeBinaryFromReader(message: Empty, reader: jspb.BinaryReader): Empty;
}

export namespace Empty {
  export type AsObject = {
  }
}

export class NetworkName extends jspb.Message {
  getSsid(): string;
  setSsid(value: string): NetworkName;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): NetworkName.AsObject;
  static toObject(includeInstance: boolean, msg: NetworkName): NetworkName.AsObject;
  static serializeBinaryToWriter(message: NetworkName, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): NetworkName;
  static deserializeBinaryFromReader(message: NetworkName, reader: jspb.BinaryReader): NetworkName;
}

export namespace NetworkName {
  export type AsObject = {
    ssid: string,
  }
}

export class User extends jspb.Message {
  getMacaddress(): string;
  setMacaddress(value: string): User;

  getIpv4address(): string;
  setIpv4address(value: string): User;

  getPort(): number;
  setPort(value: number): User;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): User.AsObject;
  static toObject(includeInstance: boolean, msg: User): User.AsObject;
  static serializeBinaryToWriter(message: User, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): User;
  static deserializeBinaryFromReader(message: User, reader: jspb.BinaryReader): User;
}

export namespace User {
  export type AsObject = {
    macaddress: string,
    ipv4address: string,
    port: number,
  }
}

export class Packet extends jspb.Message {
  getFrom(): User | undefined;
  setFrom(value?: User): Packet;
  hasFrom(): boolean;
  clearFrom(): Packet;

  getTo(): User | undefined;
  setTo(value?: User): Packet;
  hasTo(): boolean;
  clearTo(): Packet;

  getProtocol(): string;
  setProtocol(value: string): Packet;

  getData(): Uint8Array | string;
  getData_asU8(): Uint8Array;
  getData_asB64(): string;
  setData(value: Uint8Array | string): Packet;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Packet.AsObject;
  static toObject(includeInstance: boolean, msg: Packet): Packet.AsObject;
  static serializeBinaryToWriter(message: Packet, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Packet;
  static deserializeBinaryFromReader(message: Packet, reader: jspb.BinaryReader): Packet;
}

export namespace Packet {
  export type AsObject = {
    from?: User.AsObject,
    to?: User.AsObject,
    protocol: string,
    data: Uint8Array | string,
  }
}

export class DeauthRequest extends jspb.Message {
  getNetwork(): NetworkName | undefined;
  setNetwork(value?: NetworkName): DeauthRequest;
  hasNetwork(): boolean;
  clearNetwork(): DeauthRequest;

  getUserAddr(): string;
  setUserAddr(value: string): DeauthRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeauthRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DeauthRequest): DeauthRequest.AsObject;
  static serializeBinaryToWriter(message: DeauthRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeauthRequest;
  static deserializeBinaryFromReader(message: DeauthRequest, reader: jspb.BinaryReader): DeauthRequest;
}

export namespace DeauthRequest {
  export type AsObject = {
    network?: NetworkName.AsObject,
    userAddr: string,
  }
}

export class NetworkList extends jspb.Message {
  getNamesList(): Array<string>;
  setNamesList(value: Array<string>): NetworkList;
  clearNamesList(): NetworkList;
  addNames(value: string, index?: number): NetworkList;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): NetworkList.AsObject;
  static toObject(includeInstance: boolean, msg: NetworkList): NetworkList.AsObject;
  static serializeBinaryToWriter(message: NetworkList, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): NetworkList;
  static deserializeBinaryFromReader(message: NetworkList, reader: jspb.BinaryReader): NetworkList;
}

export namespace NetworkList {
  export type AsObject = {
    namesList: Array<string>,
  }
}

export class DecryptRequest extends jspb.Message {
  getSsid(): string;
  setSsid(value: string): DecryptRequest;

  getPasswd(): string;
  setPasswd(value: string): DecryptRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DecryptRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DecryptRequest): DecryptRequest.AsObject;
  static serializeBinaryToWriter(message: DecryptRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DecryptRequest;
  static deserializeBinaryFromReader(message: DecryptRequest, reader: jspb.BinaryReader): DecryptRequest;
}

export namespace DecryptRequest {
  export type AsObject = {
    ssid: string,
    passwd: string,
  }
}

export class DecryptResponse extends jspb.Message {
  getState(): DecryptState;
  setState(value: DecryptState): DecryptResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DecryptResponse.AsObject;
  static toObject(includeInstance: boolean, msg: DecryptResponse): DecryptResponse.AsObject;
  static serializeBinaryToWriter(message: DecryptResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DecryptResponse;
  static deserializeBinaryFromReader(message: DecryptResponse, reader: jspb.BinaryReader): DecryptResponse;
}

export namespace DecryptResponse {
  export type AsObject = {
    state: DecryptState,
  }
}

export class NetworkInfo extends jspb.Message {
  getBssid(): string;
  setBssid(value: string): NetworkInfo;

  getName(): string;
  setName(value: string): NetworkInfo;

  getChannel(): number;
  setChannel(value: number): NetworkInfo;

  getEncryptedPacketCount(): number;
  setEncryptedPacketCount(value: number): NetworkInfo;

  getDecryptedPacketCount(): number;
  setDecryptedPacketCount(value: number): NetworkInfo;

  getClientsList(): Array<ClientInfo>;
  setClientsList(value: Array<ClientInfo>): NetworkInfo;
  clearClientsList(): NetworkInfo;
  addClients(value?: ClientInfo, index?: number): ClientInfo;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): NetworkInfo.AsObject;
  static toObject(includeInstance: boolean, msg: NetworkInfo): NetworkInfo.AsObject;
  static serializeBinaryToWriter(message: NetworkInfo, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): NetworkInfo;
  static deserializeBinaryFromReader(message: NetworkInfo, reader: jspb.BinaryReader): NetworkInfo;
}

export namespace NetworkInfo {
  export type AsObject = {
    bssid: string,
    name: string,
    channel: number,
    encryptedPacketCount: number,
    decryptedPacketCount: number,
    clientsList: Array<ClientInfo.AsObject>,
  }
}

export class ClientInfo extends jspb.Message {
  getAddr(): string;
  setAddr(value: string): ClientInfo;

  getIsDecrypted(): boolean;
  setIsDecrypted(value: boolean): ClientInfo;

  getHandshakeNum(): number;
  setHandshakeNum(value: number): ClientInfo;

  getCanDecrypt(): boolean;
  setCanDecrypt(value: boolean): ClientInfo;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ClientInfo.AsObject;
  static toObject(includeInstance: boolean, msg: ClientInfo): ClientInfo.AsObject;
  static serializeBinaryToWriter(message: ClientInfo, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ClientInfo;
  static deserializeBinaryFromReader(message: ClientInfo, reader: jspb.BinaryReader): ClientInfo;
}

export namespace ClientInfo {
  export type AsObject = {
    addr: string,
    isDecrypted: boolean,
    handshakeNum: number,
    canDecrypt: boolean,
  }
}

export class FocusState extends jspb.Message {
  getFocused(): boolean;
  setFocused(value: boolean): FocusState;

  getName(): NetworkName | undefined;
  setName(value?: NetworkName): FocusState;
  hasName(): boolean;
  clearName(): FocusState;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): FocusState.AsObject;
  static toObject(includeInstance: boolean, msg: FocusState): FocusState.AsObject;
  static serializeBinaryToWriter(message: FocusState, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): FocusState;
  static deserializeBinaryFromReader(message: FocusState, reader: jspb.BinaryReader): FocusState;
}

export namespace FocusState {
  export type AsObject = {
    focused: boolean,
    name?: NetworkName.AsObject,
  }
}

export class File extends jspb.Message {
  getName(): string;
  setName(value: string): File;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): File.AsObject;
  static toObject(includeInstance: boolean, msg: File): File.AsObject;
  static serializeBinaryToWriter(message: File, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): File;
  static deserializeBinaryFromReader(message: File, reader: jspb.BinaryReader): File;
}

export namespace File {
  export type AsObject = {
    name: string,
  }
}

export class RecordingsList extends jspb.Message {
  getFilesList(): Array<File>;
  setFilesList(value: Array<File>): RecordingsList;
  clearFilesList(): RecordingsList;
  addFiles(value?: File, index?: number): File;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RecordingsList.AsObject;
  static toObject(includeInstance: boolean, msg: RecordingsList): RecordingsList.AsObject;
  static serializeBinaryToWriter(message: RecordingsList, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RecordingsList;
  static deserializeBinaryFromReader(message: RecordingsList, reader: jspb.BinaryReader): RecordingsList;
}

export namespace RecordingsList {
  export type AsObject = {
    filesList: Array<File.AsObject>,
  }
}

export class NewMayhemState extends jspb.Message {
  getState(): boolean;
  setState(value: boolean): NewMayhemState;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): NewMayhemState.AsObject;
  static toObject(includeInstance: boolean, msg: NewMayhemState): NewMayhemState.AsObject;
  static serializeBinaryToWriter(message: NewMayhemState, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): NewMayhemState;
  static deserializeBinaryFromReader(message: NewMayhemState, reader: jspb.BinaryReader): NewMayhemState;
}

export namespace NewMayhemState {
  export type AsObject = {
    state: boolean,
  }
}

export class LEDState extends jspb.Message {
  getState(): boolean;
  setState(value: boolean): LEDState;

  getColor(): Color;
  setColor(value: Color): LEDState;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): LEDState.AsObject;
  static toObject(includeInstance: boolean, msg: LEDState): LEDState.AsObject;
  static serializeBinaryToWriter(message: LEDState, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): LEDState;
  static deserializeBinaryFromReader(message: LEDState, reader: jspb.BinaryReader): LEDState;
}

export namespace LEDState {
  export type AsObject = {
    state: boolean,
    color: Color,
  }
}

export enum DecryptState { 
  SUCCESS = 0,
  WRONG_OR_NO_DATA = 1,
  ALREADY_DECRYPTED = 2,
  WRONG_NETWORK_NAME = 3,
}
export enum Color { 
  RED = 0,
  YELLOW = 1,
  GREEN = 2,
}
