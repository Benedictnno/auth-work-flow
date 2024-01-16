const sendEmail = require("./sendEmail");

const sendResetPassword = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  const resetUrl = `${origin}/user/reset-password?token=${verificationToken}&email=${email}`;

  const message = `<p>Please reset  your password by clicking on the following link: <a href="${resetUrl}"> Reset Password </a></p>`;
  return sendEmail({
    to: email,
    subject: "Reset Password",
    html: `<h4>Hello ${name}</h4> ${message}`,
  });
};

module.exports = sendResetPassword;
