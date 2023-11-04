    //Declarar variables constantes
const express= require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const path = require("path");
const app= express(); 

    //Configuraciones
app.set("view engine", "ejs"),
app.set("views", path.join(__dirname, "views"));
app.use("/assets",express.static("assets"));
app.use(bodyParser.urlencoded({ extended: true}));

app.listen (3000, (req,res)=> {
    console.log("Corriendo en el puerto 3000")
})

    //Conexion a base de datos
const db = mysql.createConnection({
    host: "localhost",
    port: "3308",
    user: "root",
    password: "",
    database: "car_minder"
});

db.connect((err)=>{
    if (err){
        console.log("Error al conectar a la base de datos: " + err.stack);
    } 
    else{
        console.log("Conexión exitosa a la base de datos");
    }
})

    // Paginas 
app.get("/Car-Minder",(req,res)=>{
    res.render("index",{})
})

    //Register
app.post("/register", (req, res)=>{
    const{nombre_u, correo_u, contraseña_u} = req.body;
    const query= "INSERT INTO usuario (nombre_u, contraseña_u, correo_u) VALUES (?, ?, ?)";
    db.query(query, [nombre_u, contraseña_u, correo_u], (err, result)=>{
        if (err){
            console.error("Error al registrar usuario: ", err);
            res.send("Error al registrar el usuario");
        } else {
            console.log("Usuario registrado con éxito");
            res.send("Usuario registrado con éxito");
        }
    });
});