import { Router } from "express";

let router = Router();

/* GET users listing. */
router.get("/", (res) => {
  res.send("respond with a resource");
});

export default router;
