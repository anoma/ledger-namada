/** ******************************************************************************
 *  (c) 2018 - 2022 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */
import Zemu from '@zondax/zemu'
import { NamadaApp, ResponseSignMasp, ResponseSpendSign, Signature } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions, MASP_TRANSFER_SIGNING_TX, MASP_TRANSFER_TX, zip32_path, tx_ibc_masp } from './common'
import { hashSignatureSec } from './utils'

// @ts-ignore
import ed25519 from 'ed25519-supercop'

jest.setTimeout(120000)

const MASP_MODELS = models.filter(m => m.name !== 'nanos')

const TEST_SIGN_DATA = {
  name: 'transfer',
  blob: Buffer.from(MASP_TRANSFER_SIGNING_TX, 'hex'),
  sectionHashes: {
    0: Buffer.from('0474ae7280f687ac6d95367da481479c7145e60fa94cbb94b67d4130f5e636bd', 'hex'),
    1: Buffer.from('1f07d555db2430f5dbf51e1f70ce0852affeb8d5791a6957a9895b40ce79e726', 'hex'),
    2: Buffer.from('a4fa85bd4b2205d4fd51e438bf65c95edf3503236ec0ffbe3a471524af2efa24', 'hex'),
    3: Buffer.from('0cadb91730d8d5904469534807019c50300e492afd8aa118d91482c5c8f7d657', 'hex'),
    4: Buffer.from('e860b624d11094f3a1782ed504e391d608db583423c940bd040e012a14efd917', 'hex'),
    5: Buffer.from('93d490522af5054c06cf65eb493de80159d1cd55fe40a5971fdb4766910a57d7', 'hex'),
    0xff: Buffer.from('f2cb1effd9d5bb3091d9772d2a6d341f1620c59f8043e2acf8323b2dc4c924e3', 'hex'),
  } as { [index: number]: Buffer },
}

describe('Masp', function () {
  test.concurrent.each(MASP_MODELS)('Get randomness', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const respSpend = await app.getSpendRandomness()
      console.log(respSpend)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respSpend1 = await app.getSpendRandomness()
      console.log(respSpend1)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respOutput = await app.getOutputRandomness()
      console.log(respOutput)
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')

      const respRandomness = await app.getConvertRandomness()
      console.log(respRandomness)
      expect(respRandomness.returnCode).toEqual(0x9000)
      expect(respRandomness.errorMessage).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Sign MASP Spends', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      // Compute randomness Not having effect on this test harcoded values inside
      const respSpend = await app.getSpendRandomness()
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')
      const respConvert = await app.getConvertRandomness()
      expect(respConvert.errorMessage).toEqual('No errors')
      const respOutput = await app.getOutputRandomness()
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')

      const msg = Buffer.from(MASP_TRANSFER_TX, 'hex')

      //Sign and verify returned hash
      const respRequest = app.signMaspSpends(zip32_path, msg)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_masp_spends`)

      const resp: ResponseSignMasp = (await respRequest) as ResponseSignMasp
      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

      //Extract Signture for the spend
      const respSpendSign = app.getSpendSignature()
      const resp2: ResponseSpendSign = (await respSpendSign) as ResponseSpendSign
      console.log(resp2)
      expect(resp2.returnCode).toEqual(0x9000)
      expect(resp2.errorMessage).toEqual('No errors')

      // Try to get next non existant signature
      const respSpendSign2 = app.getSpendSignature()
      const resp3: ResponseSpendSign = (await respSpendSign2) as ResponseSpendSign
      console.log(resp3)
      expect(resp3.returnCode).toEqual(0x6984)
      expect(resp3.errorMessage).toEqual('Data is invalid')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Sign MASP', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)
      // console.log(resp_addr)

      const respRequest = app.sign(hdpath, TEST_SIGN_DATA.blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-masp-${TEST_SIGN_DATA.name}`)

      const resp = await respRequest
      // console.log(resp, m.name, data.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      const signature = resp.signature ?? new Signature()
      expect(signature.rawPubkey).toEqual(resp_addr.rawPubkey)
      console.log(signature)
      // Verify raw signature
      const unsignedRawSigHash = hashSignatureSec([], signature.raw_salt, TEST_SIGN_DATA.sectionHashes, signature.raw_indices, null, null)
      const rawSig = ed25519.verify(signature.raw_signature.subarray(1), unsignedRawSigHash, signature.rawPubkey.subarray(1))

      // Verify wrapper signature
      const prefix = new Uint8Array([0x03])
      const rawHash: Buffer = hashSignatureSec(
        [signature.rawPubkey],
        signature.raw_salt,
        TEST_SIGN_DATA.sectionHashes,
        signature.raw_indices,
        signature.raw_signature,
        prefix,
      )
      const tmpHashes = { ...TEST_SIGN_DATA.sectionHashes }

      tmpHashes[Object.keys(tmpHashes).length - 1] = rawHash

      const unsignedWrapperSigHash = hashSignatureSec([], signature.wrapper_salt, tmpHashes, signature.wrapper_indices, null, null)
      const wrapperSig = ed25519.verify(signature.wrapper_signature.subarray(1), unsignedWrapperSigHash, resp_addr.rawPubkey.subarray(1))

      expect(wrapperSig && rawSig).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Clean randomness Buffers', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const respSpend = await app.getSpendRandomness()
      console.log(respSpend)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respOutput = await app.getOutputRandomness()
      console.log(respOutput)
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')

      const respRandomness = await app.getConvertRandomness()
      console.log(respRandomness)
      expect(respRandomness.returnCode).toEqual(0x9000)
      expect(respRandomness.errorMessage).toEqual('No errors')

      const respClean = await app.cleanRandomnessBuffers()
      console.log(respClean)
      expect(respClean.returnCode).toEqual(0x9000)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Wrong MASP starting instruction', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const respClean = await app.cleanRandomnessBuffers()
      console.log(respClean)
      expect(respClean.returnCode).toEqual(0x9000)

      // Wrong MASP starting INS no randomness was computed or spends signed
      const resp = await app.getSpendSignature()

      // Expect the specific return code and error message
      expect(resp.returnCode).toEqual(27012)
      expect(resp.errorMessage).toEqual('Data is invalid')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Wrong MASP sequence', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      // First step: compute randomness
      const respSpend = await app.getSpendRandomness()
      console.log(respSpend)
      expect(respSpend.returnCode).toEqual(0x9000)
      expect(respSpend.errorMessage).toEqual('No errors')

      const respOutput = await app.getOutputRandomness()
      console.log(respOutput)
      expect(respOutput.returnCode).toEqual(0x9000)
      expect(respOutput.errorMessage).toEqual('No errors')

      const respRandomness = await app.getConvertRandomness()
      console.log(respRandomness)
      expect(respRandomness.returnCode).toEqual(0x9000)
      expect(respRandomness.errorMessage).toEqual('No errors')

      // Missing spend signature and trying to extract the signatures
      const resp = await app.getSpendSignature()
      console.log(resp)

      // Expect the specific return code and error message
      expect(resp.returnCode).toEqual(27012)
      expect(resp.errorMessage).toEqual('Data is invalid')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(MASP_MODELS)('Sign IBC MASP Issue 105', async function (m) {
  const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)
      // console.log(resp_addr)

      const respRequest = app.sign(hdpath, Buffer.from(tx_ibc_masp, 'hex'))
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-masp-ibc`)

      const resp = await respRequest
      // console.log(resp, m.name, data.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

    } finally {
      await sim.close()
    }
  })
})
