# TapoJS
 A NodeJS library for interfacing with Tapo smart products. Only on/off is supported as of now.
 
 ## Installation
 
```bash
npm install tapojs
```

## Usage

```js
const Tapo = require('tapojs');

async function main(){
    const tapo = await new Tapo().connect("192.168.X.XXX", "mail@example.com", "Passw0rd!");
    await tapo.turnOn();
    await tapo.turnOff();
};

main();
```
