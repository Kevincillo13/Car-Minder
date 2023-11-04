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
    database: "carminder"
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
    app.post("/register", (req, res) => {
        const { nombre_u, correo_u, contraseña_u } = req.body;
      
        // Verificar si el correo electrónico ya existe en la base de datos
        const queryCheck = "SELECT * FROM usuarios WHERE correo_u = ?";
        db.query(queryCheck, [correo_u], (err, results) => {
          if (err) {
            console.error("Error al verificar el correo electrónico: ", err);
            res.status(500).send('<script>alert("Error al verificar el correo electrónico"); window.location="/Car-Minder";</script>');
          } else if (results.length > 0) {
            // El correo electrónico ya está en uso
            res.status(400).send('<script>alert("El correo electrónico ya está en uso. Por favor, elija otro."); window.location="/Car-Minder";</script>');
          } else {
            // El correo electrónico no está en uso, procede con la inserción
            const query = "INSERT INTO usuarios (nombre_u, contraseña_u, correo_u, created_at, active) VALUES (?, ?, ?, NOW(), 1)";
            db.query(query, [nombre_u, contraseña_u, correo_u], (err, result) => {
              if (err) {
                console.error("Error al registrar usuario: ", err);
                res.status(500).send('<script>alert("Error al registrar al usuario"); window.location="/Car-Minder";</script>');
              } else {
                console.log("Usuario registrado con éxito");
      
                // Muestra una alerta en el navegador del cliente
                res.send('<script>alert("Usuario registrado con éxito"); window.location="/Car-Minder";</script>');
              }
            });
          }
        });
      });