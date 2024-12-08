// Importar dependencias
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Crear la app de Express
const app = express();
app.use(bodyParser.json());

// Configuración del puerto
const PORT = process.env.PORT || 4000;

// Simulación de una base de datos en memoria
const users = [];

// **Endpoint para registrar usuarios**
app.post('/api/register', async (req, res) => {
    const { username, password, email } = req.body;

    // Verificar si el usuario ya existe
    const userExists = users.find(user => user.username === username);
    if (userExists) {
        return res.status(400).json({ message: 'El usuario ya existe' });
    }

    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Guardar el usuario
    const newUser = { username, password: hashedPassword, email };
    users.push(newUser);

    res.status(201).json({ message: 'Usuario registrado exitosamente', user: newUser });
});

// **Endpoint para iniciar sesión**
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // Buscar el usuario
    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Verificar la contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    // Crear un token de autenticación
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ message: 'Inicio de sesión exitoso', token });
});

// Middleware para autenticar el token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token no proporcionado' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });
        req.user = user;
        next();
    });
};

// **Endpoint para acceder a un recurso protegido**
app.get('/api/protected-resource', authenticateToken, (req, res) => {
    res.status(200).json({ message: 'Acceso a recurso protegido', user: req.user });
});

// **Endpoint para cerrar sesión**
app.post('/api/logout', authenticateToken, (req, res) => {
    // Nota: La invalidación del token debe ser manejada en el cliente.
    res.status(200).json({ message: 'Cierre de sesión exitoso' });
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
