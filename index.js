const express = require("express")
const app = express()
const cors = require("cors")
const jwt = require('jsonwebtoken');
require('dotenv').config()
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY)
const port = process.env.PORT || 5000;

//middlewares
app.use(cors())
app.use(express.json())

//jwt middleware
const verifyJWT = (req, res, next) =>{
  const authorization = req.headers.authorization;
  if(!authorization){
    return res.status(401).send({error: true, message: 'unauthorized access'})
  }
  //bearer token
  const token = authorization.split(' ')[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded)=> {
    if(error){
      return res.status(401).send({error: true, message: 'unauthorized access you try'})
    }
    req.decoded = decoded;
    next()
  })
}

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.cgmlfql.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();

    //database all collections
    const teachersCollection = client.db("languageDb").collection('teachers')
    const classesCollection = client.db("languageDb").collection('classes')
    const selectsCollection = client.db("languageDb").collection('selects')
    const usersCollection = client.db("languageDb").collection('users')
    const paymentCollection = client.db("languageDb").collection('payments')

    app.post('/jwt', (req, res)=>{
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '72h' })
      return res.send({token})
    })

    //admin verify
    const verifyAdmin = async(req, res, next) =>{
      const email = req.decoded.email;
      const query = {email: email}
      const user = await usersCollection.findOne(query);
      if(user?.role !== 'admin'){
        return res.status(403).send({error: true, message: 'forbidden message'})
      }
      next()
    }

    //instructor verify
    const verifyInstructor = async(req, res, next) =>{
      const email = req.decoded.email;
      const query = {email: email}
      const user = await usersCollection.findOne(query);
      if(user?.role !== 'instructor'){
        return res.status(403).send({error: true, message: 'forbidden message'})
      }
      next()
    }

    //users related api use verifyJWT
    app.get('/users', verifyJWT, verifyAdmin,  async(req, res) =>{
      const result = await usersCollection.find().toArray()
      return res.send(result)
    })

    app.post('/users', async(req, res) =>{
      const user = req.body;
      const query = {email: user.email}
      const existingUser = await usersCollection.findOne(query)
      if(existingUser){
        return res.send({message: 'existing user'})
      }
      const result = await usersCollection.insertOne(user);
      res.send(result)
    })

    //admin verify get request
    app.get('/users/admin/:email', verifyJWT, async(req, res) => {
      const email = req.params.email;
      const query = {email: email}

      if(req.decoded.email !== email){
        return res.send({admin: false})
      }
      const user = await usersCollection.findOne(query)
      const result = {admin: user?.role === 'admin'}
      res.send(result)
    })

    //make admin patch
    app.patch('/users/admin/:id', async(req, res)=>{
      const id = req.params.id;
      const filter = {_id: new ObjectId(id)}
      const updateDoc = {
        $set: {
          role: 'admin',
        },
      };
      const result = await usersCollection.updateOne(filter, updateDoc)
      res.send(result)
    })

    //instructor verify get request
    app.get('/users/instructor/:email', verifyJWT, async(req, res) => {
      const email = req.params.email;
      const query = {email: email}
      if(req.decoded.email !== email){
        return res.send({instructor: false})
      }
      const user = await usersCollection.findOne(query)
      const result = {instructor: user?.role === 'instructor'}
      res.send(result)
    })

    app.patch('/users/instructor/:id', async(req, res)=>{
      const id = req.params.id;
      const filter = {_id: new ObjectId(id)}
      const updateDoc = {
        $set: {
          role: 'instructor',
        },
      };
      const result = await usersCollection.updateOne(filter, updateDoc)
      res.send(result)
    })

    //teachers related apis
    app.get('/teachers', async(req, res) =>{
        const result = await teachersCollection.find().toArray()
        res.send(result)
    })

    //class related apis
    app.get('/classes', async(req, res) =>{
        const result = await classesCollection.find().toArray()
        res.send(result)
    })
//upload class
    app.post('/classes',  async(req, res) =>{
      const newClass = req.body;
      const result = await classesCollection.insertOne(newClass)
      res.send(result)
    })

    app.get('/myclass', verifyJWT, async(req, res)=>{
      const email = req.query.email;
      if(!email){
        return res.send([])
      }

      const decodedEmail = req.decoded.email;
      if(email != decodedEmail){
        return res.status(401).send({error: true, message: 'forbidden access you try'})
      }

      const query = { email: email }
      const result = await classesCollection.find(query).toArray()
      res.send(result)
    })

    //select class related api user email base data get and used teacher base classes
    app.get('/selects', verifyJWT, async(req, res)=>{
      const email = req.query.email;
      if(!email){
        return res.send([])
      }

      const decodedEmail = req.decoded.email;
      if (email !== decodedEmail) {
        return res.status(403).send({ error: true, message: 'forbidden access' })
      }

      const query = { email: email }
      const result = await selectsCollection.find(query).toArray();
      res.send(result)
    })

    app.post('/selects', async(req, res)=>{
        const item = req.body;
        const result = await selectsCollection.insertOne(item)
        res.send(result)
    })

    app.delete('/selects/:id', verifyJWT, async(req, res)=>{
      const id = req.params.id;
      const query = {_id: new ObjectId(id)}
      const result = await selectsCollection.deleteOne(query)
      res.send(result)
    })

    //payment related api
    app.post('/create-payment-intent', verifyJWT, async(req, res) => {
      const { price } = req.body;
      const amount = parseInt(price * 100)
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: 'usd',
        payment_method_types:['card']
      });
      res.send({
        clientSecret: paymentIntent.client_secret,
      })
    })

    //payment
    app.post('/payments', verifyJWT, async(req, res)=>{
      const payment = req.body;
      const insertResult = await paymentCollection.insertOne(payment)

      const query = {_id: {$in: [new ObjectId(payment.classId)]}}
      const deleteResult = await selectsCollection.deleteOne(query)
      res.send({insertResult, deleteResult})
    })

    app.get('/payments/:email', async (req, res) => {
      try {
        const email = req.params.email;
        const query = { email: email };
        const payments = await paymentCollection.find(query).toArray();
        res.send( payments );
      } catch (error) {
        res.status(500).send({ success: false, error: 'An error occurred' });
      }
    });



    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req, res) =>{
    res.send('admisition is going on')
})

app.listen(port, ()=>{
    console.log(`language school is running: ${port}`);
})

/**
 * here is some problem
 * 1. payment system
 * 2. single email base payment system
 * 3. middle ware use fix some problem
*/
