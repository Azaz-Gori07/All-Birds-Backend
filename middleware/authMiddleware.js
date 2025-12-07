import jwt from "jsonwebtoken";




export const authenticateToken = (req, res, next) => {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) return res.status(403).json({ error: "No token provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ error: "Invalid token" });

        req.user = user;
        next();
    });
};


export const authorizeRoles = (...allowedRoles) => {
    return (req, res, next) => {
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: "Access denied" });
        }
        next();
    };
};



export const verifyUser = (req, res, next) => {
    console.log("adbasndm");
    
    const token = req.headers.authorization?.split(" ")[1];
    console.log("danish");

    if (!token) {
        return res.status(401).json({ message: "Please login first" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        console.log("azaz");
        
        next();
    } catch (error) {
        console.log("error");
        return res.status(401).json({ message: "Invalid or expired token" });
    }
};
