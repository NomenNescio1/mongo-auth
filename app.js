const express = require('express');
const mongo = require('mongoose');
var cookieSession = require('cookie-session');
//var bodyParser = require('body-parser');
var bcrypt = require('bcrypt');

const app = express();
const saltRounds = 10;
app.set('view engine', 'pug');
app.set('views', 'views');
app.use(express.urlencoded({ extended: true }));

app.use(cookieSession({
    secret: 'holaasdljaslkjdsalksadlkjsadlk',  
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))


var schema = mongo.Schema({
    email: String,
    password: String,
    name: String    
});

var User = mongo.model('User', schema);
mongo.connect(process.env.MONGODB_URL || 'mongodb://localhost:27017/mongo-autenticar', {useNewUrlParser:true,  useUnifiedTopology: true });
mongo.connection.on('error', (e)=>{console.error(e)});

const requireUser = async (req, res, next) => {
    const userId = req.session.userId;
    if (userId) {
      const user = await User.findOne({ _id: userId });
      //res.locals.user = user;
      next();
    } else {
      return res.redirect("/login");
    }
  }
const isLoggedIn = (req, res, next)=>{
    if(req.session.userId){
        return res.redirect('/');
    }
    else{
        next();
    }
}

app.get('/login', isLoggedIn, (req, res)=>{
    res.render('form', {error: null});        
});

app.get('/logout', (req, res)=>{
    req.session.userId = null;
    return res.redirect('/login');
});
app.get('/', requireUser, async (req, res)=>{
    const users = await User.find(); 
    res.render("users", { users: users }); 
});

app.get('/register', isLoggedIn,(req,res)=>{
    res.render('form-register');
});
app.post('/register',async (req,res)=>{
    
    const currentUser = await User.findOne({ email: req.body.email });
    if(currentUser){
        res.render('form', {message: 'user exists, login?'});
    }
    else{
        var salt = bcrypt.genSaltSync(saltRounds);
        var hash = bcrypt.hashSync(req.body.password, salt);
        await User.create({email:req.body.email, password:hash, name: req.body.name});
        const createdUser = await User.findOne({email:req.body.email})
        req.session.userId = createdUser._id;
        return res.redirect('/');
    }
})
app.post('/login', async (req, res)=>{
    const currentUser = await User.findOne({ email: req.body.email });
    if(currentUser){
        try {
            bcrypt.compare(req.body.password, currentUser.password, function(err, exists) {
                if(exists) {
                    req.session.userId = currentUser._id;
                    return res.redirect('/');
                } else {
                    res.render('form', {message:'wrong password'})
                } 
              });           
        } catch (error) {        
            console.log(error);
        }        
    }else{
        res.render('form-register', {message: 'user not found, register?'})
    }    
})

app.listen(3000, () => console.log('Listening on port 3000!'));
