const express = require("express");
const session = require("express-session");
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const secret = "carmensemeperdiolacadenita";
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const path = require("path");
const app = express();
const validator = require('validator');
const flash = require('express-flash');

const { OAuth2Client } = require('google-auth-library');

const client = new OAuth2Client({
  clientId: '823356872551-9erkje3ta43i09laa77r3f63h3ulnvep.apps.googleusercontent.com',
  clientSecret: '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',
  redirectUri: 'http://localhost:3000/carminder/auth/google/callback' // URI de redireccionamiento autorizado
});


// Configuraciones
app.set("view engine", "ejs"),
app.set("views", path.join(__dirname, "views"));
app.use("/assets", express.static("assets"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: secret,
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Conexion a base de datos
const db = mysql.createConnection({
    host: "localhost",
    port: "3308",
    user: "root",
    password: "",
    database: "carminder"
});

db.connect((err) => {
    if (err) {
        console.log("Error al conectar a la base de datos: " + err.stack);
    } else {
        console.log("Conexión exitosa a la base de datos");
    }
});

// Configuración de Passport para trabajar con sesiones
passport.serializeUser((user, done) => {
    done(null, user.id_usuario); // Utilizar el ID del usuario en la sesión
});

passport.deserializeUser((id, done) => {
    // Obtener detalles del usuario desde la base de datos usando el ID
    const query = "SELECT * FROM usuarios WHERE id_usuario = ?";
    db.query(query, [id], (err, results) => {
        if (err) {
            console.error("Error al buscar el usuario: ", err);
            return done(err);
        }

        if (results.length === 0) {
            console.log("Usuario no encontrado");
            return done(null, false, { message: 'Usuario no encontrado' });
        }

        const usuario = results[0];
        return done(null, usuario);
    });
});

// Configuración de Passport para la estrategia local de autenticación   
passport.use(new LocalStrategy(
    { usernameField: 'correo_u', passwordField: 'contraseña_u', failureFlash: true },
    (correo_u, contraseña_u, done) => {
        console.log(`Intento de inicio de sesión para el correo: ${correo_u}`);

        // Validaciones
        if (!correo_u || !contraseña_u) {
            return done(null, false, { message: 'Correo electrónico y contraseña son obligatorios' });
        }

        // Consulta para verificar si el correo electrónico existe
        const query = "SELECT * FROM usuarios WHERE correo_u = ?";
        db.query(query, [correo_u], (err, results) => {
            if (err) {
                console.error("Error al buscar el usuario: ", err);
                return done(err);
            }

            if (results.length === 0) {
                // El correo electrónico no está registrado
                return done(null, false, { message: 'Correo electrónico no registrado' });
            }

            const usuario = results[0];

            // Comparar contraseñas
            bcrypt.compare(contraseña_u, usuario.contraseña_u, (err, result) => {
                if (err) {
                    console.error("Error al comparar contraseñas: ", err);
                    return done(err);
                }

                if (result) {
                    console.log("Inicio de sesión exitoso");
                    return done(null, usuario);
                } else {
                    // Contraseña incorrecta
                    return done(null, false, { message: 'Contraseña incorrecta' });
                }
            });
        });
    }
));

// Rutas
app.get("/CarMinder", (req, res) => {
    const errorMessage = req.query.error === '1' ? 'Correo electrónico no registrado o contraseña incorrecta' : '';
    res.render("CarMinder", { errorMessage });
});

app.get("/register", (req, res) => {
    res.render("register", {})
});

app.get("/foro", (req, res) => {
    res.render("Foro", { user: req.user });
});

// Ruta Estado
app.get("/estado/:id_carro_usuario", ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const idCarroUsuario = req.params.id_carro_usuario;

    // Obtener la información específica del coche del usuario desde la tabla carros_usuarios
    const queryCarrosUsuarios = "SELECT * FROM carros_usuarios WHERE id_usuario = ? AND id_carro_usuario = ?";

    db.query(queryCarrosUsuarios, [userId, idCarroUsuario], (err, resultsCarrosUsuarios) => {
        if (err) {
            console.error("Error al obtener información del coche del usuario desde carros_usuarios: ", err);
            res.status(500).send("Error al obtener información del coche del usuario");
            return;
        }

        const coche = resultsCarrosUsuarios[0]; // Tomamos el primer resultado, asumiendo que la consulta devuelve un solo resultado

        // Asegúrate de que 'coche' esté definido antes de continuar
        if (!coche) {
            res.status(404).send("Coche no encontrado en la tabla carros_usuarios");
            return;
        }

        // Obtener información adicional del coche desde la tabla carros usando el modelo
        const queryCarros = "SELECT * FROM carros WHERE modelo = ?";

        db.query(queryCarros, [coche.modelo], (err, resultsCarros) => {
            if (err) {
                console.error("Error al obtener información adicional del coche desde carros: ", err);
                res.status(500).send("Error al obtener información del coche del usuario");
                return;
            }

            const cocheBase = resultsCarros[0]; // Tomamos el primer resultado, asumiendo que la consulta devuelve un solo resultado

            // Asegúrate de que 'cocheBase' esté definido antes de renderizar la página
            if (cocheBase) {
                res.render("Estado", { user: req.user, coche: coche, cocheBase: cocheBase });
            } else {
                res.status(404).send("Coche no encontrado en la tabla carros");
            }
        });
    });
});


app.get("/configuracion", ensureAuthenticated, (req, res) => {
    res.render("configuracion", { user: req.user });
});

app.get("/agregarCoche", ensureAuthenticated, (req, res) => {
    res.render("agregarCoche", { user: req.user });
});

// En tu ruta de inicio, donde obtienes los coches para mostrar en la página principal
app.get("/inicio", ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const query = "SELECT * FROM carros_usuarios WHERE id_usuario = ?";
    
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Error al obtener coches del usuario: ", err);
            res.status(500).send("Error al obtener coches del usuario");
        } else {
            // Renderiza la página de inicio y pasa los coches del usuario y la información del usuario
            res.render("inicio", { coches: results, user: req.user });
        }
    });
});

// Inicio de sesión
app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            // Usuario no encontrado
            return res.render('CarMinder', { errorMessage: 'Correo electrónico no registrado' });
        }
        req.logIn(user, (err) => {
            if (err) {
                return next(err);
            }
            return res.redirect('/Inicio');
        });
    })(req, res, next);
});


// Registro de usuario
app.post("/register", (req, res) => {
    const { nombre_u, correo_u, contraseña_u } = req.body;

    if (!nombre_u || !correo_u || !contraseña_u) {
        return res.status(400).send('<script>alert("Todos los campos son obligatorios"); window.location="/CarMinder";</script>');
    }

    if (!validator.isEmail(correo_u)) {
        return res.status(400).send('<script>alert("Correo electrónico no válido"); window.location="/CarMinder";</script>');
    }

    // Verificar si el correo electrónico ya está registrado
    const checkEmailQuery = "SELECT * FROM usuarios WHERE correo_u = ?";

    db.query(checkEmailQuery, [correo_u], (err, results) => {
        if (err) {
            console.error("Error al verificar el correo electrónico: ", err);
            res.status(500).send('<script>alert("Error al registrar"); window.location="/CarMinder";</script>');
            return;
        }

        if (results.length > 0) {
            // El correo electrónico ya está registrado
            res.status(400).send('<script>alert("El correo electrónico ya está en uso"); window.location="/CarMinder";</script>');
            return;
        }

        // Si no hay resultados, proceder con la inserción
        bcrypt.hash(contraseña_u, 10, (err, hash) => {
            if (err) {
                console.error("Error al encriptar la contraseña: ", err);
                res.status(500).send('<script>alert("Error al registrar"); window.location="/CarMinder";</script>');
            } else {
                const insertUserQuery = "INSERT INTO usuarios (nombre_u, correo_u, contraseña_u, created_at, active) VALUES (?, ?, ?, NOW(), 1)";
                db.query(insertUserQuery, [nombre_u, correo_u, hash], (err, results) => {
                    if (err) {
                        console.error("Error al registrar el usuario: ", err);
                        res.status(500).send('<script>alert("Error al registrar"); window.location="/CarMinder";</script>');
                    } else {
                        res.send('<script>alert("Usuario registrado con éxito"); window.location="/CarMinder";</script>');
                    }
                });
            }
        });
    });
});


// Ruta para cerrar sesión
app.get('/cerrar-sesion', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Error al cerrar sesión:", err);
            return next(err);
        }
        console.log("Sesión cerrada con éxito");
        res.redirect('CarMinder');
    });
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/CarMinder'); // Redirigir a la página de inicio de sesión si no está autenticado
}

//AgregarCoche
app.post('/agregarCoche', ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const { marca, modelo, km_actual, uc_llantas, uc_aceite, uc_frenos, uc_liquido_frenos, uc_aceite_direccion, uc_filtro_aire, uc_bujias, uc_correas, uc_filtro_combustible, uc_suspension, uc_liquido_transmision } = req.body;
    console.log('Valores recibidos en la solicitud:', req.body);

    // Generar la ruta de la imagen
    const ruta_imagen = `/assets/imagenes/Vehiculos automotrices/${marca} ${modelo}.jpg`;

    // Insertar datos en la base de datos
    const query = "INSERT INTO carros_usuarios (id_usuario, marca, modelo, km_actual, uc_llantas, uc_aceite, uc_frenos, uc_liquido_frenos, uc_aceite_direccion, uc_filtro_aire, uc_bujias, uc_correas, uc_filtro_combustible, uc_suspension, uc_liquido_transmision, ruta_imagen, fecha_registro) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())";
    
    db.query(query, [userId, marca, modelo, km_actual, uc_llantas, uc_aceite, uc_frenos, uc_liquido_frenos, uc_aceite_direccion, uc_filtro_aire, uc_bujias, uc_correas, uc_filtro_combustible, uc_suspension, uc_liquido_transmision, ruta_imagen], (error, result) => {
        if (error) {
            console.error('Error al procesar el formulario de agregar coche:', error.message);
            console.error(error.stack);
            res.status(500).send('Error interno del servidor');
        } else {
            // Redireccionar a la página de inicio después de agregar el coche
            res.redirect('/inicio');
        }
    });
});

// Ruta para actualizar el nombre
app.post('/actualizar-nombre', ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const nuevoNombre = req.body.nombre_u;

    // Actualizar el nombre en la base de datos
    const updateNombreQuery = "UPDATE usuarios SET nombre_u = ? WHERE id_usuario = ?";
    
    db.query(updateNombreQuery, [nuevoNombre, userId], (error, result) => {
        if (error) {
            console.error('Error al actualizar el nombre:', error.message);
            res.status(500).send('Error interno del servidor');
        } else {
            res.send('<script>alert("Nombre de usuario actualizado con éxito"); window.location="/Configuracion";</script>');
 // Redirigir a la página de configuración después de la actualización
        }
    });
});

// Ruta para actualizar el correo
app.post('/actualizar-correo', ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const nuevoCorreo = req.body.correo_u;

    // Actualizar el nombre en la base de datos
    const updateCorreoQuery = "UPDATE usuarios SET correo_u = ? WHERE id_usuario = ?";
    
    db.query(updateCorreoQuery, [nuevoCorreo, userId], (error, result) => {
        if (error) {
            console.error('Error al actualizar el correo electrónico:', error.message);
            res.status(500).send('Error interno del servidor');
        } else {
            res.send('<script>alert("Correo electrónico actualizado con éxito"); window.location="/Configuracion";</script>');
 // Redirigir a la página de configuración después de la actualización
        }
    });
});

// Ruta para eliminar cuenta
app.post('/eliminar-cuenta', ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;

    // Actualizar el nombre en la base de datos
    const EliminarCuenta = "DELETE FROM usuarios WHERE id_usuario = ?";
    
    db.query(EliminarCuenta, [userId], (error, result) => {
        if (error) {
            console.error('Error al eliminar usuario', error.message);
            res.status(500).send('Error interno del servidor');
        } else {
            res.send('<script>alert("Usuario eliminado con éxito"); window.location="/CarMinder";</script>');
 // Redirigir a la página de configuración después de la actualización
        }
    });
});

// Ruta para eliminar un coche
app.post('/eliminar-coche', ensureAuthenticated, (req, res) => {
    const userId = req.user.id_usuario;
    const cocheId = req.body.id_carro_usuario;

    // Realizar la eliminación en la base de datos
    const eliminarCocheQuery = "DELETE FROM carros_usuarios WHERE id_usuario = ? AND id_carro_usuario = ?";

    db.query(eliminarCocheQuery, [userId, cocheId], (error, result) => {
        if (error) {
            console.error('Error al eliminar el coche:', error.message);
            res.status(500).send('Error interno del servidor');
        } else {
            // Redirigir a la página de inicio u otra página después de la eliminación
            res.redirect('/inicio'); // Cambia la ruta según sea necesario
        }
    });
});


// Iniciar el servidor
app.listen(3000, () => {
    console.log("Corriendo en el puerto 3000");
});


