const express = require('express');
const db = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cookieParser());

function verificarToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).json({ error: 'No autenticado' });
    }

    try {
        const decoded = jwt.verify(token, SECRET);
        req.usuario = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Token inválido' });
    }
}

function autorizarRoles(...rolesPermitidos) {
    return (req, res, next) => {
        if (!rolesPermitidos.includes(req.usuario.rol)) {
            return res.status(403).json({ error: 'No tienes permisos para esta acción' });
        }
        next();
    };
}

app.post('/register', async (req, res) => {
    const { nombre, email, password } = req.body;

    if (!nombre || !email || !password) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    try {
        // Encriptar contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = 'INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)';
        const values = [nombre, email, hashedPassword];

        db.query(sql, values, (err, results) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ error: 'Email ya registrado' });
                }
                return res.status(500).json({ error: err.message });
            }

            res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
        });

    } catch (error) {
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

const SECRET = "clave_super_secreta";

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Faltan campos' });
    }

    const sql = 'SELECT * FROM usuarios WHERE email = ?';

    db.query(sql, [email], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });

        if (results.length === 0) {
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }

        const usuario = results[0];

        const passwordCorrecta = await bcrypt.compare(password, usuario.password);

        if (!passwordCorrecta) {
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        // Crear token
        const token = jwt.sign(
            { id: usuario.id, email: usuario.email , rol: usuario.rol },
            SECRET,
            { expiresIn: '1h' }
        );

        // Enviarlo como cookie segura
        res.cookie('token', token, {
            httpOnly: true,
            secure: false, // en producción true (HTTPS)
            sameSite: 'strict',
            maxAge: 3600000
        });

        res.json({ mensaje: 'Login correcto' });
    });
});

app.get('/cargadores', (req, res) => {
    const sql = 'SELECT * FROM cargadores';

    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

app.post('/cargadores',
	verificarToken,
	autorizarRoles('admin'),
	(req, res) => {
		const { tipo, estado, latitud, longitud, velocidad_carga_kw, precio_kw } = req.body;

		if (!tipo || !estado || !latitud || !longitud || !velocidad_carga_kw || !precio_kw) {
		 return res.status(400).json({ error: 'Faltan campos obligatorios' });
		}

		const sql = 'INSERT INTO cargadores (tipo, estado, latitud, longitud, velocidad_carga_kw, precio_kw) VALUES (?, ?, ?, ?, ?, ?)';
		const values = [tipo, estado, latitud, longitud, velocidad_carga_kw, precio_kw];

		db.query(sql, values, (err, results) => {
			if (err) {
				return res.status(500).json({ error: err.message });
			}

			// Devuelve el nuevo cargador con el id generado
			const nuevoCargador = {
				id: results.insertId,
				tipo,
				estado,
				latitud,
				longitud,
				velocidad_carga_kw,
				precio_kw
			};

			res.status(201).json({ mensaje: 'Cargador creado correctamente', cargador: nuevoCargador });
		});
	}
);

app.put('/cargadores/:id',
     verificarToken,
     autorizarRoles('admin'),
	(req, res) => {
		const { id } = req.params;
		const { tipo, estado, latitud, longitud, velocidad_carga_kw, precio_kw } = req.body;

		if (!tipo || !estado || !latitud || !longitud || !velocidad_carga_kw || !precio_kw) {
	        return res.status(400).json({ error: 'Faltan campos obligatorios' });
		}

		const sql = 'UPDATE cargadores SET tipo=?, estado=?, latitud=?, longitud=?, velocidad_carga_kw=?, precio_kw=? WHERE id=?';
		const values = [tipo, estado, latitud, longitud, velocidad_carga_kw, precio_kw, id];

		db.query(sql, values, (err, results) => {
		    if (err) return res.status(500).json({ error: err.message });
		    if (results.affectedRows === 0) return res.status(404).json({ error: 'Cargador no encontrado' });

		    res.json({ mensaje: 'Cargador actualizado correctamente' });
		});
	}
);

app.put('/cargadores/:id/estado',
    verificarToken,
    autorizarRoles('admin', 'tecnico'),
    (req, res) => {

        const { id } = req.params;
        const { estado } = req.body;

        if (!estado) {
            return res.status(400).json({ error: 'Debe indicar el nuevo estado' });
        }

        const sql = 'UPDATE cargadores SET estado = ? WHERE id = ?';

        db.query(sql, [estado, id], (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            if (results.affectedRows === 0)
                return res.status(404).json({ error: 'Cargador no encontrado' });

            res.json({ mensaje: 'Estado actualizado correctamente' });
        });
    }
);

app.delete('/cargadores/:id',
	verificarToken,
	autorizarRoles('admin'),
	(req, res) => {
		const { id } = req.params;

		const sql = 'DELETE FROM cargadores WHERE id=?';
		db.query(sql, [id], (err, results) => {
			if (err) return res.status(500).json({ error: err.message });
			if (results.affectedRows === 0) return res.status(404).json({ error: 'Cargador no encontrado' });

			res.json({ mensaje: 'Cargador eliminado correctamente' });
		});
	}
);

app.post('/reservas',
	verificarToken,
	autorizarRoles('usuario'),
	(req, res) => {
		const { cargador_id, duracion_minutos } = req.body;

		if (!cargador_id || !duracion_minutos) {
		    return res.status(400).json({ error: 'Faltan datos' });
		}

		const usuario_id = req.usuario.id;

	    // 1️⃣ Verificar que el cargador existe y está libre
		const sqlCheck = 'SELECT estado FROM cargadores WHERE id = ?';

		db.query(sqlCheck, [cargador_id], (err, results) => {
		    if (err) return res.status(500).json({ error: err.message });

			if (results.length === 0) {
		        return res.status(404).json({ error: 'Cargador no encontrado' });
		    }

		    if (results[0].estado !== 'libre') {
		        return res.status(400).json({ error: 'El cargador no está disponible' });
		    }

		    // 2️⃣ Calcular fechas
		    const fecha_inicio = new Date();
		    const fecha_fin = new Date(fecha_inicio.getTime() + duracion_minutos * 60000);

			// 3️⃣ Crear reserva
			const sqlInsert = `
			    INSERT INTO reservas (usuario_id, cargador_id, fecha_inicio, fecha_fin)
			    VALUES (?, ?, ?, ?)
			`;

			db.query(sqlInsert, [usuario_id, cargador_id, fecha_inicio, fecha_fin], (err, results) => {
			    if (err) return res.status(500).json({ error: err.message });

			    // 4️⃣ Cambiar estado del cargador a ocupado
			    const sqlUpdate = 'UPDATE cargadores SET estado = "ocupado" WHERE id = ?';

			    db.query(sqlUpdate, [cargador_id], (err) => {
			        if (err) return res.status(500).json({ error: err.message });

			        res.status(201).json({
			            mensaje: 'Reserva creada y cargador marcado como ocupado',
			            reserva_id: results.insertId
			        });
			    });
			});
		});
	}
);

app.put('/reservas/:id/cancelar',
	verificarToken,
	autorizarRoles('usuario'),
	(req, res) => {

		const reserva_id = req.params.id;
	    const usuario_id = req.usuario.id;

	    // 1️⃣ Verificar que la reserva existe y pertenece al usuario
	    const sqlCheck = `
	        SELECT * FROM reservas 
	        WHERE id = ? AND usuario_id = ? AND estado = 'activa'
	    `;

	    db.query(sqlCheck, [reserva_id, usuario_id], (err, results) => {
	        if (err) return res.status(500).json({ error: err.message });

	        if (results.length === 0) {
	            return res.status(404).json({ error: 'Reserva no encontrada o no autorizada' });
	        }

	        const cargador_id = results[0].cargador_id;

	        // 2️⃣ Cancelar reserva
	        const sqlUpdateReserva = `
	            UPDATE reservas 
	            SET estado = 'cancelada' 
	            WHERE id = ?
	        `;

	        db.query(sqlUpdateReserva, [reserva_id], (err) => {
	            if (err) return res.status(500).json({ error: err.message });

	            // 3️⃣ Liberar cargador
	            const sqlUpdateCargador = `
	                UPDATE cargadores 
	                SET estado = 'libre' 
	                WHERE id = ?
	            `;

	            db.query(sqlUpdateCargador, [cargador_id], (err) => {
	                if (err) return res.status(500).json({ error: err.message });

	                res.json({ mensaje: 'Reserva cancelada y cargador liberado' });
	            });
	        });
	    });
	}
);

app.get('/reservas',
	verificarToken,
	autorizarRoles('usuario'),
	(req, res) => {

		const usuario_id = req.usuario.id;

	    const sql = `
	        SELECT r.*, c.tipo, c.estado AS estado_cargador
	        FROM reservas r
	        JOIN cargadores c ON r.cargador_id = c.id
	        WHERE r.usuario_id = ?
	        ORDER BY r.fecha_creacion DESC
	    `;

	    db.query(sql, [usuario_id], (err, results) => {
	        if (err) return res.status(500).json({ error: err.message });

	        res.json(results);
	    });
	}
);

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
