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
import static java.util.Collections.singletonList;

import tech.pegasys.orion.testutil.OrionTestHarness;
import tech.pegasys.pantheon.crypto.Hash;
import tech.pegasys.pantheon.ethereum.core.Address;
import tech.pegasys.pantheon.ethereum.rlp.BytesValueRLPOutput;
import tech.pegasys.pantheon.tests.acceptance.dsl.node.PantheonNode;
import tech.pegasys.pantheon.tests.acceptance.dsl.privacy.PrivateAcceptanceTestBase;
import tech.pegasys.pantheon.tests.acceptance.dsl.transaction.eea.PrivateTransactionBuilder;
import tech.pegasys.pantheon.tests.acceptance.dsl.transaction.eea.PrivateTransactionBuilder.TransactionType;
import tech.pegasys.pantheon.util.bytes.Bytes32;
import tech.pegasys.pantheon.util.bytes.BytesValue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

import com.google.common.collect.Lists;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

@SuppressWarnings({"UnnecessaryLocalVariable", "WeakerAccess"})
public class PrivacyClusterAcceptanceTest extends PrivateAcceptanceTestBase {
  private static final Logger LOG = LogManager.getLogger();
  private String privacyGroup012;
  private String privacyGroup01;

  PrivacyNet privacyNet = new PrivacyNet(privacy, pantheon, cluster);

  @Before
  public void setUp() throws Exception {
    privacyNet.initPreknownConfig1();
    LOG.info("Privacy Network Config: " + privacyNet);
    privacyGroup012 =
        generatePrivacyGroupId(
            Arrays.asList(node(0).orionPubKey, node(1).orionPubKey, node(2).orionPubKey));
    privacyGroup01 =
        generatePrivacyGroupId(node(0).orionPubKey, singletonList(node(1).orionPubKey));
    privacyNet.startPantheonNodes();
    privacyNet.verifyAllOrionNetworkConnections();
  }

  @After
  public void tearDown() {
    privacyNet.stop();
  }

  public PrivacyNode node(final int i) {
    return privacyNet.getNodes().get(i);
  }

  public PantheonNode pantheon(final int i) {
    return privacyNet.getNodes().get(i).pantheon;
  }

  @SuppressWarnings("unused")
  public OrionTestHarness orion(final int i) {
    return privacyNet.getNodes().get(i).orion;
  }

  public static String generatePrivacyGroupIdFromBytes(final List<byte[]> pgList) {
    final BytesValueRLPOutput rlpOutput = new BytesValueRLPOutput();
    final List<BytesValue> rlpList =
        pgList.stream()
            .sorted(Comparator.comparing(Arrays::hashCode))
            .map(BytesValue::wrap)
            .distinct()
            .collect(Collectors.toList());

    rlpOutput.startList();
    for (BytesValue bytesValue : rlpList) {
      rlpOutput.writeBytesValue(bytesValue);
    }
    rlpOutput.endList();
    BytesValue rlpEncoded = rlpOutput.encoded();

    Bytes32 hash = Hash.keccak256(rlpEncoded);
    byte[] b64 = Base64.getEncoder().encode(hash.getArrayUnsafe());
    String privacyGroupId = BytesValue.wrap(b64).toString();

    return privacyGroupId;
  }

  /** Generates the privacy group from Base64 encoded byte arrays */
  @SuppressWarnings("unused")
  public static String generatePrivacyGroupId(
      final byte[] privateFrom, final List<byte[]> privateFor) {
    final List<byte[]> pgList = new ArrayList<>();
    pgList.add(Base64.getDecoder().decode(privateFrom));
    privateFor.forEach(item -> pgList.add(Base64.getDecoder().decode(item)));
    return generatePrivacyGroupIdFromBytes(pgList);
  }

  /** Generates the privacy group from Base64 encoded Strings */
  public static String generatePrivacyGroupId(final List<String> participants) {
    final List<byte[]> pgList = new ArrayList<>();
    participants.forEach(item -> pgList.add(Base64.getDecoder().decode(item.getBytes(UTF_8))));
    return generatePrivacyGroupIdFromBytes(pgList);
  }

  /** Generates the privacy group from Base64 encoded Strings */
  public static String generatePrivacyGroupId(
      final String privateFrom, final List<String> privateFor) {
    final List<String> participants = new ArrayList<>();
    participants.add(privateFrom);
    participants.addAll(privateFor);
    return generatePrivacyGroupId(participants);
  }

  public String buildDeployContractTx(final int fromNode, final int[] privateForNodes) {
    long nonce = node(fromNode).getNonce(privateForNodes);
    return buildDeployContractTx(fromNode, nonce, privateForNodes);
  }

  public String buildDeployContractTx(
      final int fromNode, final Long nonce, final int[] privateForNodes) {
    // Get the Orion public keys for the node numbers given in privateForNodes
    List<BytesValue> privateForOrionKeys =
        Arrays.stream(privateForNodes)
            .mapToObj(i -> node(i).getOrionPubKeyBytes())
            .collect(Collectors.toList());

    String deployTx =
        PrivateTransactionBuilder.builder()
            .nonce(nonce)
            .from(pantheon(fromNode).getAddress())
            .to(null)
            .privateFrom(node(fromNode).getOrionPubKeyBytes())
            .privateFor(privateForOrionKeys)
            .keyPair(node(fromNode).pantheonNodeKeypair)
            .build(TransactionType.CREATE_CONTRACT);
    return deployTx;
  }

  public String buildGetValueTx(final int fromNode, final Address to, final int[] privateForNodes) {
    // Get the Orion public keys for the node numbers given in privateForNodes
    List<BytesValue> privateForOrionKeys =
        Arrays.stream(privateForNodes)
            .mapToObj(i -> node(i).getOrionPubKeyBytes())
            .collect(Collectors.toList());

    String deployTx =
        PrivateTransactionBuilder.builder()
            .nonce(node(fromNode).getNonce(privateForNodes))
            .from(pantheon(fromNode).getAddress())
            .to(to)
            .privateFrom(node(fromNode).getOrionPubKeyBytes())
            .privateFor(privateForOrionKeys)
            .keyPair(node(fromNode).pantheonNodeKeypair)
            .build(TransactionType.GET);
    return deployTx;
  }

  public String buildStoreValueTx(
      final int fromNode, final Address to, final int[] privateForNodes) {
    // Get the Orion public keys for the node numbers given in privateForNodes
    List<BytesValue> privateForOrionKeys =
        Arrays.stream(privateForNodes)
            .mapToObj(i -> node(i).getOrionPubKeyBytes())
            .collect(Collectors.toList());

    String deployTx =
        PrivateTransactionBuilder.builder()
            .nonce(node(fromNode).getNonce(privateForNodes))
            .from(pantheon(fromNode).getAddress())
            .to(to)
            .privateFrom(node(fromNode).getOrionPubKeyBytes())
            .privateFor(privateForOrionKeys)
            .keyPair(node(fromNode).pantheonNodeKeypair)
            .build(TransactionType.STORE);
    return deployTx;
  }

  @Test
  public void onlyNodes01CanSeeContract() {
    long nextNonce = node(0).getNonce(new int[] {1});
    String deployTx = buildDeployContractTx(0, nextNonce, new int[] {1});

    final Address contractFor01 =
        Address.privateContractAddress(
            pantheon(0).getAddress(), nextNonce, BytesValue.fromHexString(privacyGroup01));

    String txHash = pantheon(0).execute(privateTransactions.deployPrivateSmartContract(deployTx));

    privateTransactionVerifier
        .validPrivateContractDeployed(contractFor01.toString())
        .verify(pantheon(1), txHash);
    privateTransactionVerifier
        .validPrivateContractDeployed(contractFor01.toString())
        .verify(pantheon(0), txHash);
    privateTransactionVerifier.noPrivateContractDeployed().verify(pantheon(2), txHash);
  }

  @Test
  public void onlyNodes01CanExecuteContract() {
    long nextNonce = node(0).getNonce(new int[] {1});
    String deployTx = buildDeployContractTx(0, nextNonce, new int[] {1});
    final Address contractFor01 =
        Address.privateContractAddress(
            pantheon(0).getAddress(), nextNonce, BytesValue.fromHexString(privacyGroup01));
    String txHash = pantheon(0).execute(privateTransactions.deployPrivateSmartContract(deployTx));
    privateTransactionVerifier
        .validPrivateContractDeployed(contractFor01.toString())
        .verify(pantheon(1), txHash);

    String storeTx = buildStoreValueTx(1, contractFor01, new int[] {0});
    txHash = pantheon(1).execute(privateTransactions.createPrivateRawTransaction(storeTx));
    privateTransactionVerifier.validEventReturned("1000").verify(pantheon(0), txHash);
    // TODO: Test both nodes 0 and 1
  }

  @Test
  public void node1CanSeePrivateTransactionReceipt() {
    long nextNonce = node(0).getNonce(new int[] {1});
    String deployTx = buildDeployContractTx(0, nextNonce, new int[] {1});
    String txHash = pantheon(0).execute(privateTransactions.deployPrivateSmartContract(deployTx));
    final Address contractFor01 =
        Address.privateContractAddress(
            pantheon(0).getAddress(), nextNonce, BytesValue.fromHexString(privacyGroup01));
    privateTransactionVerifier
        .validPrivateContractDeployed(contractFor01.toString())
        .verify(pantheon(1), txHash);

    String storeTx = buildStoreValueTx(1, contractFor01, new int[] {0});
    txHash = pantheon(1).execute(privateTransactions.createPrivateRawTransaction(storeTx));
    privateTransactionVerifier.validEventReturned("1000").verify(pantheon(0), txHash);

    String getTx = buildGetValueTx(1, contractFor01, new int[] {0});
    txHash = pantheon(1).execute(privateTransactions.createPrivateRawTransaction(getTx));
    privateTransactionVerifier.validOutputReturned("1000").verify(pantheon(1), txHash);
    privateTransactionVerifier.validOutputReturned("1000").verify(pantheon(0), txHash);
  }

  @Test
  public void node2CannotSeeContract() {
    String deployTx = buildDeployContractTx(0, new int[] {1});
    final String txHash =
        pantheon(0).execute(privateTransactions.deployPrivateSmartContract(deployTx));
    privateTransactionVerifier.noPrivateContractDeployed().verify(pantheon(2), txHash);
  }

  @Test
  public void node2CannotExecuteContract() {
    long nextNonce = node(0).getNonce(new int[] {1});
    String deployTx = buildDeployContractTx(0, nextNonce, new int[] {1});
    pantheon(0).execute(privateTransactions.deployPrivateSmartContract(deployTx));
    final Address contractFor01 =
        Address.privateContractAddress(
            pantheon(0).getAddress(), nextNonce, BytesValue.fromHexString(privacyGroup01));

    String getTx = buildGetValueTx(2, contractFor01, new int[] {1});
    String txHash = pantheon(2).execute(privateTransactions.createPrivateRawTransaction(getTx));
    privateTransactionVerifier.noValidOutputReturned().verify(pantheon(2), txHash);
  }

  @Test(expected = RuntimeException.class)
  public void node1ExpectError() {
    long nextNonce = node(0).getNonce(new int[] {1});
    String deployTx = buildDeployContractTx(0, nextNonce, new int[] {1});
    pantheon(0).execute(privateTransactions.deployPrivateSmartContract(deployTx));
    final Address contractFor01 =
        Address.privateContractAddress(
            pantheon(0).getAddress(), nextNonce, BytesValue.fromHexString(privacyGroup01));

    String invalidStoreValueFromNode2 =
        PrivateTransactionBuilder.builder()
            .nonce(0)
            .from(pantheon(1).getAddress())
            .to(contractFor01)
            .privateFrom(node(0).getOrionPubKeyBytes()) // wrong public key
            .privateFor(Lists.newArrayList(node(1).getOrionPubKeyBytes()))
            .keyPair(node(1).pantheonNodeKeypair)
            .build(TransactionType.STORE);

    pantheon(1)
        .execute(privateTransactions.createPrivateRawTransaction(invalidStoreValueFromNode2));
  }

  @Test
  public void privactyGroupIdGenerationIsCorrect() {
    final String privacyGroup01 =
        "0x4479414f69462f796e70632b4a586132594147423062436974536c4f4d4e6d2b53686d422f374d364334773d";
    String orionPubKey_node0 = "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=";
    String orionPubKey_node1 = "Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs=";

    String privateFrom = orionPubKey_node0;
    final List<String> privateFor = new ArrayList<>();
    privateFor.add(orionPubKey_node0);
    privateFor.add(orionPubKey_node1);
    Assert.assertEquals(privacyGroup01, generatePrivacyGroupId(privateFrom, privateFor));
  }

  @Test
  public void node1CanInteractWithMultiplePrivacyGroups2() {
    long nextNonce;
    String txHash;

    nextNonce = node(0).getNonce(new int[] {1, 2});
    String deployTx = buildDeployContractTx(0, nextNonce, new int[] {1, 2});
    txHash = pantheon(0).execute(privateTransactions.deployPrivateSmartContract(deployTx));
    final Address contractFor012 =
        Address.privateContractAddress(
            pantheon(0).getAddress(), nextNonce, BytesValue.fromHexString(privacyGroup012));
    privateTransactionVerifier
        .validPrivateContractDeployed(contractFor012.toString())
        .verify(pantheon(0), txHash);

    String storeValueFor012 = buildStoreValueTx(0, contractFor012, new int[] {1, 2});
    txHash = pantheon(0).execute(privateTransactions.createPrivateRawTransaction(storeValueFor012));
    privateTransactionVerifier.validEventReturned("1000").verify(pantheon(0), txHash);

    String storeValueFor12BeforeDeployingContract =
        buildStoreValueTx(0, contractFor012, new int[] {1});
    txHash =
        pantheon(0)
            .execute(
                privateTransactions.createPrivateRawTransaction(
                    storeValueFor12BeforeDeployingContract));
    privateTransactionVerifier.noValidOutputReturned().verify(pantheon(0), txHash);

    nextNonce = node(0).getNonce(new int[] {1});
    final Address contractFor01 =
        Address.privateContractAddress(
            pantheon(0).getAddress(), nextNonce, BytesValue.fromHexString(privacyGroup01));
    String deployContractFor01 = buildDeployContractTx(0, nextNonce, new int[] {1});
    txHash =
        pantheon(0).execute(privateTransactions.deployPrivateSmartContract(deployContractFor01));
    privateTransactionVerifier
        .validPrivateContractDeployed(contractFor01.toString())
        .verify(pantheon(0), txHash);

    String storeValueFor12 = buildStoreValueTx(0, contractFor01, new int[] {1});
    txHash = pantheon(0).execute(privateTransactions.createPrivateRawTransaction(storeValueFor12));
    privateTransactionVerifier.validEventReturned("1000").verify(pantheon(0), txHash);
  }
}
