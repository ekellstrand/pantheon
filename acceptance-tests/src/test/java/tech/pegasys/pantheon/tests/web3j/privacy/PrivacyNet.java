/*
 * Copyright 2019 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.pantheon.tests.web3j.privacy;

import static java.nio.charset.StandardCharsets.UTF_8;
import static tech.pegasys.pantheon.tests.acceptance.dsl.privacy.PrivateAcceptanceTestBase.getPrivacyParameters;

import tech.pegasys.orion.testutil.OrionTestHarness;
import tech.pegasys.orion.testutil.OrionTestHarnessFactory;
import tech.pegasys.pantheon.controller.KeyPairUtil;
import tech.pegasys.pantheon.crypto.SECP256K1;
import tech.pegasys.pantheon.tests.acceptance.dsl.node.PantheonNode;
import tech.pegasys.pantheon.tests.acceptance.dsl.node.cluster.Cluster;
import tech.pegasys.pantheon.tests.acceptance.dsl.node.factory.PantheonNodeFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import com.google.common.io.Files;
import net.consensys.cava.bytes.Bytes;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.rules.TemporaryFolder;

public class PrivacyNet {
  private static final Logger LOG = LogManager.getLogger();

  private static final SECP256K1.KeyPair PANTHEON_KEYPAIR_NODE_1 =
      KeyPairUtil.loadKeyPairFromResource("key");
  private static final SECP256K1.KeyPair PANTHEON_KEYPAIR_NODE_2 =
      KeyPairUtil.loadKeyPairFromResource("key1");
  private static final SECP256K1.KeyPair PANTHEON_KEYPAIR_NODE_3 =
      KeyPairUtil.loadKeyPairFromResource("key2");

  private static final List<SECP256K1.KeyPair> KNOWN_PANTHEON_KEYPAIRS = new ArrayList<>();

  private TemporaryFolder temporaryFolder;
  private PantheonNodeFactory pantheonNodeFactory;
  private Cluster cluster;
  private List<PrivacyNode> nodes = null;

  static {
    KNOWN_PANTHEON_KEYPAIRS.add(PANTHEON_KEYPAIR_NODE_1);
    KNOWN_PANTHEON_KEYPAIRS.add(PANTHEON_KEYPAIR_NODE_2);
    KNOWN_PANTHEON_KEYPAIRS.add(PANTHEON_KEYPAIR_NODE_3);
  }

  public PrivacyNet(
      final TemporaryFolder temporaryFolder,
      final PantheonNodeFactory pantheonNodeFactory,
      final Cluster cluster) {
    this.temporaryFolder = temporaryFolder;
    this.pantheonNodeFactory = pantheonNodeFactory;
    this.cluster = cluster;
  }

  public List<PrivacyNode> getNodes() {
    return nodes;
  }

  @SuppressWarnings("unused")
  public PantheonNode getPantheon(final int i) {
    // todo verify valid int and nodes()
    return nodes.get(i).pantheon;
  }

  /**
   * Initialize Test config with pre-known values, so that output at all stages remains consistent
   * across runs.
   */
  public void initPreknownConfig1() throws IOException, NoSuchAlgorithmException {
    nodes = new ArrayList<>();
    nodes.add(makeNode(0, true, null, true));
    String otherOrionNodes = nodes.get(0).orion.nodeUrl(); // All nodes use node 0 for discovery
    nodes.add(makeNode(1, true, otherOrionNodes, true));
    nodes.add(makeNode(2, false, otherOrionNodes, true));
  }

  /** Initialize Test config with generated keys and values, simulating a real deployed scenario */
  @SuppressWarnings("unused")
  public void initGeneratedConfig() throws IOException, NoSuchAlgorithmException {
    nodes = new ArrayList<>();
    nodes.add(makeNode(0, true, null, false));
    String otherOrionNodes = nodes.get(0).orion.nodeUrl(); // All nodes use node 0 for discovery
    nodes.add(makeNode(1, true, otherOrionNodes, false));
    nodes.add(makeNode(2, false, otherOrionNodes, false));
  }

  protected static OrionTestHarness createEnclave(
      final TemporaryFolder temporaryFolder,
      final String pubKeyPath,
      final String privKeyPath,
      final boolean useKnownOrionKeys,
      final String... othernode)
      throws IOException, NoSuchAlgorithmException {
    OrionTestHarness orion;
    Path tmpPath = temporaryFolder.newFolder().toPath();
    if (useKnownOrionKeys) {
      orion = OrionTestHarnessFactory.create(tmpPath, pubKeyPath, privKeyPath, othernode);
    } else {
      KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      PublicKey pubKey = keyPair.getPublic();
      PrivateKey privKey = keyPair.getPrivate();

      LOG.debug("pubkey      : " + pubKey);
      LOG.debug("pubkey bytes: " + Bytes.wrap(pubKey.getEncoded()).toHexString());
      LOG.debug("pubkey b64  : " + Base64.getEncoder().encodeToString(pubKey.getEncoded()));

      LOG.debug("privkey      : " + privKey);
      LOG.debug("privkey bytes: " + Bytes.wrap(privKey.getEncoded()).toHexString());
      LOG.debug("privkey b64  : " + Base64.getEncoder().encodeToString(privKey.getEncoded()));

      orion =
          OrionTestHarnessFactory.create(
              tmpPath,
              keyPair.getPublic(),
              pubKeyPath,
              keyPair.getPrivate(),
              privKeyPath,
              othernode);
    }
    return orion;
  }

  public PrivacyNode makeNode(
      final int i,
      final boolean isMiningEnabled,
      final String otherOrionNodes,
      final boolean useKnownOrionKeys)
      throws IOException, NoSuchAlgorithmException {
    String nodeName = String.format("node%d", i);
    String orionPrivateKeyFileName = String.format("orion_key_%d.key", i);
    String orionPublicKeyFileName = String.format("orion_key_%d.pub", i);
    OrionTestHarness orion;
    if (otherOrionNodes == null) {
      // Need conditional because createEnclave will choke if passing in null
      orion =
          createEnclave(
              temporaryFolder, orionPublicKeyFileName, orionPrivateKeyFileName, useKnownOrionKeys);
    } else {
      orion =
          createEnclave(
              temporaryFolder,
              orionPublicKeyFileName,
              orionPrivateKeyFileName,
              useKnownOrionKeys,
              otherOrionNodes);
    }

    PantheonNode pantheon;
    String keyFilePath;
    // node 0's file is "key",  every other node includes node number, like "key0"
    if (i == 0) {
      keyFilePath = "key";
    } else {
      keyFilePath = String.format("key%d", i);
    }
    if (isMiningEnabled) {
      pantheon =
          pantheonNodeFactory.createPrivateTransactionEnabledMinerNode(
              nodeName, getPrivacyParameters(orion), keyFilePath);
    } else {
      pantheon =
          pantheonNodeFactory.createPrivateTransactionEnabledNode(
              nodeName, getPrivacyParameters(orion), keyFilePath);
    }
    String orionPubKey =
        Files.asCharSource(orion.getConfig().publicKeys().get(0).toFile(), UTF_8).read().trim();

    return new PrivacyNode(pantheon, orion, KNOWN_PANTHEON_KEYPAIRS.get(i), orionPubKey);
  }

  public void startPantheonNodes() {
    // Todo: Verify  init was called
    if (nodes == null)
      throw new IllegalStateException(
          "Cannot start network nodes.  init method was never called to initialize the nodes");
    List<PantheonNode> pantheonNodes =
        nodes.stream().map(sc -> sc.pantheon).collect(Collectors.toList());
    // cluster.start(pantheonNodes);
    cluster.start(pantheonNodes.get(0), pantheonNodes.get(1), pantheonNodes.get(2));
  }

  public void stopOrionNodes() {
    if (nodes == null) return; // Never started
    for (PrivacyNode node : nodes) {
      try {
        node.orion.getOrion().stop();
      } catch (RuntimeException e) {
        LOG.error(
            String.format(
                "Error stopping Orion node %s.  Logging and continuing to shutdown other nodes.",
                node.orion.nodeUrl()),
            e);
      }
    }
  }

  public void stop() {
    try {
      cluster.stop();
    } catch (RuntimeException e) {
      LOG.error("Error stopping Pantheon nodes.  Logging and continuing.", e);
    }
    try {
      stopOrionNodes();
    } catch (RuntimeException e) {
      LOG.error("Error stopping Orion nodes.  Logging and continuing.", e);
    }
  }

  /** Verify that each Orion node has connected to every other Orion */
  public void verifyAllOrionNetworkConnections() {
    for (int i = 0; i < nodes.size(); i++) {
      for (int j = i; j < nodes.size(); j++) {
        nodes.get(i).testOrionConnection(nodes.get(j));
      }
    }
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(String.format("temporaryFolder      = %s\n", temporaryFolder.getRoot()));
    for (PrivacyNode privacyNode : nodes) {
      sb.append(String.format("Pantheon Node Name   = %s\n", privacyNode.pantheon.getName()));
      sb.append(String.format("Pantheon Address     = %s\n", privacyNode.pantheon.getAddress()));
      sb.append(
          String.format(
              "Pantheon Private Key = %s\n", privacyNode.pantheonNodeKeypair.getPrivateKey()));
      sb.append(
          String.format(
              "Pantheon Public  Key = %s\n", privacyNode.pantheonNodeKeypair.getPublicKey()));
      sb.append(String.format("Orion Pub Key        = %s\n", privacyNode.getOrionPubKeyBytes()));
      sb.append(
          String.format(
              "Orion Pub Key Base64 = %s\n",
              Base64.getEncoder()
                  .encodeToString(privacyNode.getOrionPubKeyBytes().extractArray())));

      sb.append(String.format("Pantheon             = %s\n", privacyNode.pantheon));
      sb.append(String.format("Orion Config         = %s\n", privacyNode.orion.getConfig()));
      sb.append(String.format("Orion Pub Key        = %s\n", privacyNode.getOrionPubKeyBytes()));
    }
    return sb.toString();
  }
}
