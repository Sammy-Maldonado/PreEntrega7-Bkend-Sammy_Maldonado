import express from 'express';
import session from 'express-session';
import handlebars from 'express-handlebars';
import MongoStore from 'connect-mongo';
import mongoose from 'mongoose';
import { Server } from 'socket.io';
import passport from 'passport';

import viewsRouter from './routes/views.router.js'
import productsRouter from './routes/products.router.js';
import cartRouter from './routes/carts.router.js';
import sessionsRouter from './routes/session.router.js';

import registerChatHandler from './listeners/chatHandler.js';
import initializePassportStrategies from './config/passport.config.js';
import __dirname from './utils.js';

import ProductManager from '../src/dao/fileSystem/Managers/ProductManagers.js';

//import cartsModel from './dao/mongo/models/carts.js';
//import productsModel from './dao/mongo/models/products.js';

const productManager = new ProductManager();


const app = express();
const PORT = process.env.PORT || 8080;
const server = app.listen(PORT, () => console.log(`Listening on ${PORT}`));
const io = new Server(server);
const connection = mongoose.connect('mongodb+srv://CoderUser:123@cluster0.gfqujcv.mongodb.net/ecommerce?retryWrites=true&w=majority')
app.use(express.json())
app.use(express.static(`${__dirname}/public`));
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  //Referenciando nuestro io
  req.io = io;
  next();
})

//Handlebars
app.engine('handlebars', handlebars.engine());
app.set('views', `${__dirname}/views`);
app.set('view engine', 'handlebars');

app.use(session({
  store: new MongoStore({
    mongoUrl:'mongodb+srv://CoderUser:123@cluster0.gfqujcv.mongodb.net/ecommerce?retryWrites=true&w=majority',
    ttl: 3600
  }),
  secret: "CoderS3cretfelis",
  resave: true,
  saveUninitialized: false
}))

app.use(passport.initialize());
initializePassportStrategies();

app.use('/api/products', productsRouter);
app.use('/api/carts', cartRouter);
app.use('/api/sessions',sessionsRouter);
app.use('/', viewsRouter);

//Escuchador de eventos (on)
io.on('connection', socket => {
  registerChatHandler(io, socket);
});


/* Sintaxis Mongo Avanzado */
const context = async () => {
  /* Creando un producto */
  /* const product = {
    title: "productito",
    description: "dulce",
    price: 600,
    code: "21",
    stock: 10,
    category: "frutas",
    thumbnails: []
  }
  await productsModel.create(product); */

  /* Creando un carrito */
  /* const cart =
  {
    "name": "Carrito de prueba con products",
    "price": 5000
  }

  await cartsModel.create(cart); */

  /* Agregando el producto al carrito */
  /* const cartId = "646ebbefe90f24c0096376c8";
    const productId = "646a825abd9bf198a28d3494";
    
    await cartsModel.updateOne(
      { _id: cartId },
      { $push: { products: { product: new mongoose.Types.ObjectId(productId) } } }
      ); */

  //El pructo "product" queda agregado a los "products" de mi carrito, pero se agrega solo con su "Id". Es necesario poblarlo con sus propiedades para que se vean sus prespectivos "title", "description", "price", etc, dentro de él.
  /* const cart = await cartsModel.find();
  console.log(JSON.stringify(cart,null,'\t')); */

};

context();