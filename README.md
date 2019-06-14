# passport-nonce

## Install
```sh
$ npm install passport-nonce
```

## Usage
#### Configure Strategy
```js
passport.use(new NonceStrategy({
  clientHeaderName: 'x-client-name',
  nonceHeaderName: 'x-nonce',
  tokenHeaderName: 'x-token',
  clientSecrets: {
    'client1': 'averysecretsharedsecret',
    'client2': 'averysecretsharedsecret'
  }
}))
```
#### Authenticate Requests
```js
app.get('/judge',
  passport.authenticate('nonce'));
```