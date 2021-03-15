const UsersModel = require("./models/users.models");
const _ = require("lodash");
const config = require("./config");
const bcrypt = require("bcrypt");
const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");

function checkAuth(req, res, next) {
    passport.authenticate(
        "jwt",
        { session: false },
        (err, decryptToken, jwtError) => {
            if (jwtError != void 0 || err != void 0) {
                return res.render("chat.html", { error: err || jwtError });
            }
            req.user = decryptToken;
            next();
        }
    )(req, res, next);
}

function createToken(body) {
    return jwt.sign(body, config.jwt.secretOrKey, {
        expiresIn: config.expiresIn
    });
}

module.exports = app => {
    app.use("/assets", express.static("./client/public"));

    app.get("/", checkAuth, (req, res) => {
        res.render("chat.html", { username: req.user.username });
    });

    app.post("/login", async (req, res) => {
        try {
            let user = await UsersModel.findOne({
                username: { $regex: _.escapeRegExp(req.body.username), $options: "i" }
            })
                .lean()
                .exec();
            if (user && bcrypt.compareSync(req.body.password, user.password)) {
                const token = createToken({ id: user._id, username: user.username });
                res.cookie("token", token, {
                    httpOnly: true
                });

                res.status(200).send({ message: "Вход выполнен!" });
            } else
                res
                    .status(400)
                    .send({ message: "Пользователь не существует или неверный пароль" });
        } catch (e) {
            console.error("E, login,", e);
            res.status(500).send({ message: "Произошла ошибка" });
        }
    });

    app.post("/register", async (req, res) => {
        try {
            let user = await UsersModel.findOne({
                username: { $regex: _.escapeRegExp(req.body.username), $options: "i" }
            })
                .lean()
                .exec();
            if (user) {
                return res.status(400).send({ message: "Пользователь уже существует" });
            }

            user = await UsersModel.create({
                username: req.body.username,
                password: req.body.password
            });

            const token = createToken({ id: user._id, username: user.username });

            res.cookie("token", token, {
                httpOnly: true
            });

            res.status(200).send({ message: "Пользователь создан." });
        } catch (e) {
            console.error("E, register,", e);
            res.status(500).send({ message: "Произошла ошибка" });
        }
    });

    app.post("/logout", (req, res) => {
        res.clearCookie("token");
        res.status(200).send({ message: "Вы уверены?" });
    });
};