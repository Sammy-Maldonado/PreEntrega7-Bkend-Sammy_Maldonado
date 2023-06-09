import passport from 'passport';
import local from 'passport-local';
import GithubStrategy from 'passport-github2';
import userModel from '../dao/mongo/models/user.js';
import { createHash, validatePassword } from '../utils.js';


const LocalStrategy = local.Strategy;

const initializePassportStrategies = () => {
  passport.use('register', new LocalStrategy({ passReqToCallback: true, usernameField: 'email' }, async (req, email, password, done) => {
    try {
      const { first_name, last_name } = req.body;
      const exists = await userModel.findOne({ email });
      if (exists) return done(null, false, { message: 'El usuario ya existe' })
      const hashedPassword = await createHash(password);
      const user = {
        first_name,
        last_name,
        email,
        password: hashedPassword
      }
      const result = await userModel.create(user);
      done(null, result)
    } catch (error) {
      done(error)
    }
  }))

  //Todas las demas estrategias van acá, por ejemplo, la estrategia de login
  passport.use('login', new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {

    if (email === "adminCoder@coder.com" && password === "adminCod3r123") {
      const user = {
        id: 0,
        name: `Admin`,
        role: "admin",
        email: "..."
      }
      return done(null, user)
    }
    let user;
    //Buscando al usuario
    user = await userModel.findOne({ email });
    if (!user) return done(null, false, { message: "Credenciales incorrectas" })

    //Verificando su password encriptado
    const isValidPassword = await validatePassword(password, user.password);
    if (!isValidPassword) return done(null, false, { message: "Contraseña inválida" })

    //Creando la sesion del usuario
    user = {
      id: user._id,
      name: `${user.first_name} ${user.last_name}`,
      email: user.email,
      role: user.role
    }
    return done(null, user);
  }));

  passport.use(
    'github',
    new GithubStrategy(
      {
        clientID: "Iv1.91be627b8795a242",
        clientSecret: "7668c55a865f8a4a71f973d6d961d2a952f2f951",
        callbackURL: "http://localhost:8080/api/sessions/githubcallback"
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          console.log(profile);
          const {name, email} = profile._json;
          const user = await userModel.findOne({ email });
          //Creando el usuario si no existe.
          if(!user) {
            const newUser = {
              first_name: name,
              email,
              password:''
            }
            const result = await userModel.create(newUser);
            done(null, result);
          }
          //En caso de que si exista.
          done(null, user);
        } catch (error) {
          done(error);
        }
      }))

  passport.serializeUser(function (user, done) {
    return done(null, user.id);
  })
  passport.deserializeUser(async function (id, done) {
    if (id === 0) {
      return done(null, {
        role: "admin",
        name: "ADMIN"
      })
    }
    const user = await userModel.findOne({ _id: id });
    return done(null, user);
  })
}

export default initializePassportStrategies;