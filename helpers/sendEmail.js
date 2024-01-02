import nodemailer from "nodemailer";
import "dotenv/config";

const { META_PASSWORD, META_FROM } = process.env;

const nodemailerConfig = {
  host: "smtp.meta.ua",
  port: 465,
  secure: true,
  auth: {
    user: META_FROM,
    pass: META_PASSWORD,
  },
};

const transporter = nodemailer.createTransport(nodemailerConfig);

const sendEmail = (data) => {
  const email = {
    ...data,
    from: META_FROM,
  };
  return transporter.sendMail(email);
};

export default sendEmail;
