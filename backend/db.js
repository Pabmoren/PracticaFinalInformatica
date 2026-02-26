const mysql = require('mysql2');

// Crear conexión
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'node_user',
    password: 'NodePass123!',
    database: 'encuentra_tu_cargador'
});

// Conectar
connection.connect((err) => {
    if (err) {
        console.error('Error conectando a MySQL:', err);
        return;
    }
    console.log('Conectado a MySQL correctamente');
});

module.exports = connection;
