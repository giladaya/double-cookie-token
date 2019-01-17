// Inspiration:
// https://medium.com/lightrail/getting-token-authentication-right-in-a-stateless-single-page-application-57d0c6474e3

const path = require('path')
const jwt = require('jsonwebtoken')
const express = require('express')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')

const PORT = 3210
const SECRET = 'shhhhh!'

const COOKIE_SECURE = false
const COOKIE_DOMAIN = 'localhost'

const signOptions = { expiresIn: '30m' }

function checkAuth(req, res, next) {
  let token, isWeb
  if (req.headers['Authentication']) {
    token = req.headers['Authentication'].substring(7)
    isWeb = false
  } else {
    const cookie1 = req.cookies.token_header_payload
    const cookie2 = req.cookies.token_signature
    token = `${cookie1}.${cookie2}`
    isWeb = true
  }
  
  try {
    const decoded = jwt.verify(token, SECRET)
    console.log('Decoded token', decoded)
    if (isWeb) {
      const cookie1 = req.cookies.token_header_payload
      const csrfVer = req.headers['x-requested-with'] || req.query['x-requested-with']
      if (csrfVer !== cookie1) {
        throw new Error(`csrf header doesn't match cookie`)
      }
    }

    req.jwt = decoded
    return next()
  } catch (err) {
    console.error('Error', err.message)
    const noAthErr = new Error('Not authorized! Go back!')
    noAthErr.status = 400
    return next(noAthErr)
  }
}

function setDoubleCookie(res, token) {
  const tokenParts = token.split('.')
  res.cookie(
    'token_header_payload', 
    `${tokenParts[0]}.${tokenParts[1]}`, 
    { 
      // domain: COOKIE_DOMAIN,
      secure: COOKIE_SECURE, 
      maxAge: 30 * 60 * 1000, 
    }
  );
  res.cookie(
    'token_signature', 
    tokenParts[2], 
    { 
      // domain: COOKIE_DOMAIN,
      secure: COOKIE_SECURE, 
      httpOnly: true 
    }
  );
}

const app = express()
app.use(cookieParser())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.use('/www', express.static(path.join(__dirname, 'public')))

app.get('/', (req, res) => {
  res.send('This is public data!')
})

// http://localhost:3210/login?email=foo@bar.com&password=123456
app.post('/login', (req, res) => {
  const email = req.body.email
  const password = req.body.password
  if (!email || !password) {
    res.status = 400
    res.send('Missing email or password')
    return 
  }

  const token = jwt.sign({ 
    foo: 'bar', 
    email,
    roles: [
      "teamAdmin",
      "accountManager"
    ],
  }, SECRET, signOptions)
  setDoubleCookie(res, token)
  
  res.redirect('/www/');
  // res.send('Ok')
})

// Should be POST, used GET for simplifying the client
// https://gist.github.com/ziluvatar/a3feb505c4c0ec37059054537b38fc48
app.get('/refresh_token', checkAuth, (req, res) => {
  const payload = {...req.jwt}
  // remove stale values
  delete payload.iat;
  delete payload.exp;
  delete payload.nbf;
  delete payload.jti;

  const token = jwt.sign(payload, SECRET, signOptions)
  setDoubleCookie(res, token)

  res.send('Refreshed')
})

app.get('/private', checkAuth, (req, res) => {
  res.send('This is private data!')
})

app.listen(PORT, () => console.log(`Example app listening on PORT ${PORT}!`))
