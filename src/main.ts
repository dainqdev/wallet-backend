import express from "express";
import { User, Transaction, PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";
import {
  getAddress,
  hexlify,
  isAddress,
  toUtf8Bytes,
  verifyMessage,
  toUtf8String,
  getBytes,
  randomBytes,
} from "ethers";

const app = express();
const prismaClient = new PrismaClient();
const PORT = +(process.env.PORT || 8080);
const JWT_SALT = "luis-wallet";

type AuthenticateBody = {
  chainId: number;
  nonce: string;
  signature: string;
};

app.use(express.json());

app.get("/api/wallets/:address/nonce", async (req, res) => {
  if (!isAddress(req.params.address)) {
    return res.status(400).send("Invalid address");
  }
  const address = getAddress(req.params.address);
  const chainId = Number(req.query.chainId);
  if (isNaN(chainId)) {
    return res.status(400).send("Invalid chainId");
  }
  const message = createMessage(chainId);

  res.json({
    nonce: hexlify(toUtf8Bytes(message)),
  });
});

app.get("/api/wallets/me", async (req, res) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send("Unauthorized");
  }
  try {
    const user = jwt.verify(token, JWT_SALT);
    return res.json(user);
  } catch (error) {
    return res.status(401).send("Unauthorized");
  }
});

app.post("/api/wallets/:address/authenticate", async (req, res) => {
  const { chainId, nonce, signature } = req.body as AuthenticateBody;

  if (!isAddress(req.params.address)) {
    return res.status(400).send("Invalid address");
  }
  try {
    validateNonce(toUtf8String(getBytes(nonce)), chainId);
  } catch (error) {
    return res.status(400).send((error as Error).message);
  }
  const address = getAddress(req.params.address);
  if (isNaN(chainId)) {
    return res.status(400).send("Invalid chainId");
  }

  try {
    const estimateAddress = getAddress(verifyMessage(nonce, signature));
    if (estimateAddress !== address) {
      return res.status(400).send("Address in signature not match");
    }
  } catch (error) {
    return res.status(400).send("Invalid signature");
  }

  let user = await prismaClient.user
    .findFirst({
      where: {
        address: address,
      },
    })
    .catch((err) => null);

  if (!user) {
    user = await prismaClient.user.create({
      data: {
        address,
      },
    });
  }

  const token = jwt.sign(user, JWT_SALT, { expiresIn: "1d" });

  res.json({
    wallet: user,
    token,
  });
});

app.get("/api/transactions", async (req, res) => {
  const txHashs = (req.query.txhash?.toString() ?? "")
    .split(",")
    .filter((txHash) => txHash.length === 66);
  const query =
    txHashs.length > 1
      ? {
          OR: txHashs.map((txHash) => ({
            txHash: txHash,
          })),
        }
      : { txHash: txHashs[0] };

  console.log("query", query);
  console.log("query s", req.query.txhash);

  const txs = await prismaClient.transaction.findMany({
    where: query,
  });

  res.json(
    txs.map((tx) => {
      return {
        ...((tx.extraData as object) ?? {}),
        ...((tx.data as object) ?? {}),
        id: tx.id,
        txHash: tx.txHash,
        from: tx.from,
        to: tx.to,
      };
    })
  );
});

app.post("/api/transactions/:txHash", async (req, res) => {
  const txHash = req.params.txHash;
  const data = req.body;

  if (txHash.length !== 66) {
    return res.status(400).send("Invalid tx hash");
  }

  const { from, to } = data ?? {};
  if (!isAddress(from)) {
    return res.status(400).send("Invalid tx from");
  }

  if (!isAddress(to)) {
    return res.status(400).send("Invalid tx to");
  }

  const tx = await prismaClient.transaction.upsert({
    create: {
      txHash: txHash,
      data: { ...data },
      extraData: data?.extraData ?? {},
      from: getAddress(from),
      to: getAddress(to),
    },
    update: {
      extraData: data?.extraData ?? {},
    },
    where: {
      txHash: txHash,
    },
  });

  res.json(tx);
});

app.listen(PORT, () => {
  console.log("server running in port 4000");
});

function createMessage(chainId: number) {
  let now = Date.now();
  now += 5 * 60 * 1000;
  const prefix = randomBytes(8);
  return `${prefix}:${chainId}:${now}`;
}

function validateNonce(nonce: string = "", chainId: number) {
  const [_, nonceChainId, exp] = nonce.split(":");

  if (parseNumber(exp) < Date.now()) {
    throw new Error("Nonce is exprired");
  }

  if (parseNumber(nonceChainId) != chainId) {
    throw new Error("Chain id not match");
  }
}

function getUser(token: string) {
  if (!token) {
    throw Error("Unauthorized");
  }
  try {
    const user = jwt.verify(token, JWT_SALT);
    return user as { id: string; address: string };
  } catch (error) {
    throw Error("Unauthorized");
  }
}

function parseNumber(value: string, defaultValue = 0): number {
  const v = Number(value);
  if (isNaN(v)) {
    return defaultValue;
  }

  return v;
}
