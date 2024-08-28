from common import F, FunctionalCommitment, LootBoxInput, verifyEvalProofRaw
from pywebio.input import (
    input,
    input_group,
    actions,
    select,
    input_update,
    NUMBER,
    FLOAT,
    TEXT,
)
from pywebio.output import (
    put_text,
    put_markdown,
    put_code,
    put_button,
    put_image,
    use_scope,
    clear,
    popup,
    close_popup,
    put_collapse,
    scroll_to,
    put_progressbar,
    set_progressbar,
)
from pywebio.session import run_js
from pywebio import start_server
import PRB
import inspect, ast, io
from py_ecc import optimized_bn128 as curve
import matplotlib.pyplot as plt
import numpy as np
import scipy.stats as st
import math


def mapping_function(randomness: bytes):
    from hashlib import sha256

    m = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # field modulus
    while True:
        randomness = sha256(randomness).digest()
        yield int.from_bytes(randomness, "big") % m


def post_process(y):
    m = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # field modulus
    star3 = 10  # number of 3 star cards
    star2 = 30  # number of 2 star cards
    star1 = 100  # number of 1 star cards
    prob3 = 0.03
    prob2 = 0.17
    prob_cum23 = prob2 + prob3
    p = int(y) / m
    if p < prob3:
        pp = p / prob3
        idx = int(pp * star3)
        return f"3 star: card #{idx}"
    if p < prob_cum23:
        pp = (p - prob3) / prob2
        idx = int(pp * star2)
        return f"2 star: card #{idx}"
    pp = (p - prob_cum23) / (1 - prob_cum23)
    idx = int(pp * star1)
    return f"1 star: card #{idx}"


phases_images = {}
for i in range(1, 5):
    with open(f"./pic/phase{i}.png", "rb") as f:
        phases_images[f"phase{i}"] = f.read()


def main():
    run_js(
        """
window.loadscript = function loadscript({ src, type, content }) {
    const script = document.createElement('script')
    if (type) script.type = type
    if (src) script.src = src
    if (content) script.text = content
    document.head.appendChild(script)
    return new Promise((resolve, reject) => {
        script.onload = resolve
        script.onerror = reject
    })
}
loadscript({ src: 'https://cdn.jsdelivr.net/npm/brython@3.12.2/brython.min.js' })
loadscript({ src: 'https://cdn.jsdelivr.net/npm/brython@3.12.2/brython_stdlib.js' })
           """
    )
    fc = FunctionalCommitment(5, randomCoeff=True)
    commitment = fc.getCommitment()
    with use_scope("setup"):
        put_markdown("# Setup Phase")
        put_text(f"FC: {commitment}")
        put_button(
            "What is this?",
            onclick=lambda: popup(
                "Phase 1",
                [
                    put_text(
                        "In this phase, the server committ a hidden function f(x). The source code of the mapping function will be provided later for easier understanding."
                    ),
                    put_image(phases_images["phase1"]),
                ],
                size="large",
            ),
        )

    with use_scope("randomness_contribution"):
        put_markdown("# Randomness Contribution Phase")
        put_button(
            "What is this?",
            onclick=lambda: popup(
                "Phase 2",
                [
                    put_text(
                        "You can choose to contribute to PRB and get verified randomness from it, or you can enter a fake randomness for testing purpose."
                    ),
                    put_image(phases_images["phase2"]),
                ],
                size="large",
            ),
        )
        yesprb = actions(
            "Do you want to contribute to PRB?",
            [
                {"label": "Yes", "value": True},
                {"label": "No", "value": False},
            ],
        )
        if yesprb:
            entropy = input("Enter entropy:", type=TEXT)
            contribution = PRB.contribute(entropy.encode())
            put_text(f"Contribution: {contribution}")
            put_text("Getting verified PRB randomness, please wait...")
            randomness = PRB.eval(contribution)
            put_text(f"Verified PRB Randomness (hex): {randomness.hex()}")
        else:
            randomness = input(
                "Enter your fake PRB randomness (random string):", type=TEXT
            ).encode()
            put_text(f"Fake PRB Randomness (hex): {randomness.hex()}")

        put_text(
            "The randomness will be mapped to inputs using the following function:"
        )
        put_code(
            inspect.getsource(mapping_function), language="python"
        )  # publicize the mapping_function function

    inputs_generator = mapping_function(randomness)

    with use_scope("evaluation"):
        put_markdown("# Evaluation Phase")
        put_button(
            "What is this?",
            onclick=lambda: popup(
                "Phase 3",
                [
                    put_text(
                        "Now we will generates a bunch of x using the mapping function, and evaluate the hidden function f(x) at each x and post-process the result to get your Gacha result."
                    ),
                    put_image(phases_images["phase3"]),
                ],
                size="large",
            ),
        )
        xs = []
        ys = []
        pis = []
        cards = []
        with use_scope("evaluation_loop"):
            x = next(inputs_generator)
            xs.append(x)
            put_text(f"Evaluate at x = {x}")
            y, pi = fc.evalAndProofRaw(x)
            ys.append(y)
            pis.append(pi)
            put_text(f"Evaluated value y = f(x) = {y}")
            put_text(f"Evaluation Proof: {pi}")
            assert verifyEvalProofRaw(commitment, F(x), y, pi)

            put_text("The y will be going through post-processing to get the result:")
            put_code(
                inspect.getsource(post_process), language="python"
            )  # publicize the post_process function

            def run_post_process_client(y=y):
                py = f"from browser import alert\n{inspect.getsource(post_process)}\nres = post_process({y})\nalert(res)\n"
                js = "__BRYTHON__.runPythonSource(py)"
                run_js(js, py=py)

            put_button(
                "Run this on client side (powered by Brython)",
                onclick=run_post_process_client,
            )
            card = post_process(y)
            cards.append(card)
            put_text(f"You got: {card}")

            choose_manually = actions(
                "Do you want want to choose the number of evaluations manually or let statistics decide an appropriate number?",
                [
                    {"label": "Choose manually", "value": True},
                    {"label": "Let statistics decide", "value": False},
                ],
            )
            if choose_manually:
                how_much_more = int(
                    input(
                        "How many more evaluations do you want?", type=NUMBER, value=500
                    )
                )
            else:
                put_text(
                    'We call the "claimed" probability of getting a 3 star card being p0=0.03 a "Null Hypothesis".'
                )
                put_text(
                    'Assuming the "real" probability is p1, we can decide a sample size to reject the Null Hypothesis with a certain probability called statistical power.'
                )
                while True:
                    p1 = input(
                        'Enter your "assumed" real probability of getting a 3 star card (p1, p1 <= 0.015):',
                        type=FLOAT,
                    )
                    if p1 <= 0.015:
                        break
                    put_text("p1 should be less than or equal to 0.015")
                put_text(
                    "We will calculate an appropriate sample size n with statistical power 0.8"
                )
                p0 = 0.03
                z_alpha = st.norm.ppf(0.95)
                z_beta = st.norm.ppf(0.8)
                # p1 + z_beta * sqrt(p1*(1-p1)/n) <= p0 - z_alpha * sqrt(p0*(1-p0)/n)
                numerator = z_beta * math.sqrt(p1 * (1 - p1)) + z_alpha * math.sqrt(
                    p0 * (1 - p0)
                )
                denominator = p0 - p1
                n = math.ceil((numerator / denominator) ** 2)
                lhs = p1 + z_beta * math.sqrt(p1 * (1 - p1) / n)
                rhs = p0 - z_alpha * math.sqrt(p0 * (1 - p0) / n)
                put_text(f"Appropriate sample size n: {n}")
                how_much_more = n

            put_progressbar("eval_progress")
            with put_collapse("Show all evaluations"):
                for i in range(how_much_more):
                    x = next(inputs_generator)
                    xs.append(x)
                    put_text(f"Evaluate at x = {x}")
                    y, pi = fc.evalAndProofRaw(x)
                    ys.append(y)
                    pis.append(pi)
                    put_text(f"Evaluated value y = f(x) = {y}")
                    put_text(f"Evaluation Proof: {pi}")
                    card = post_process(y)
                    cards.append(card)
                    put_text(f"You got: {card}")
                    pg = i / (how_much_more - 1) if how_much_more > 1 else 1
                    set_progressbar("eval_progress", pg)

    stars = [int(card.split(" star")[0].strip()) for card in cards]
    fig, ax = plt.subplots()
    ax.hist(stars, bins=[0.5, 1.5, 2.5, 3.5], align="mid")
    ax.set_xlabel("Stars")
    ax.set_ylabel("Count")
    ax.set_title("Gacha Result")
    probabilities = {
        i: len([s for s in stars if s == i]) / len(stars) for i in range(1, 4)
    }
    # show percentage on top of bars
    for i in range(3):
        n = len([s for s in stars if s == i + 1])
        ax.text(
            i + 1,
            n,
            f"{probabilities[i + 1] * 100:.2f}%",
            ha="center",
            va="bottom",
        )
    buf = io.BytesIO()
    fig.savefig(buf)
    put_image(buf.getvalue())

    def plot_prob(p0, p1, title):
        n = len(stars)
        mu = p0
        std = (p0 * (1 - p0) / n) ** 0.5
        za = st.norm.ppf(0.95)
        lb = mu - za * std
        fig, ax = plt.subplots()
        xs = np.linspace(max(mu - 2 * std, 0), min(mu + 2 * std, 1), 2000)
        ys = 1 / (std * (2 * np.pi) ** 0.5) * np.exp(-0.5 * ((xs - mu) / std) ** 2)
        ax.plot(xs, ys, label="Normal Distribution (CLT)")
        ax.axvline(p0, color="r", linestyle="--", label="Claimed probability")
        ax.axvline(p1, color="g", linestyle="--", label="Estimated probability")
        ax.axvline(lb, color="b", linestyle="--", label="95% confidence interval")
        ax.legend()
        ax.set_xlabel("Probability")
        ax.set_ylabel("Density")
        ax.set_title(title)
        buf = io.BytesIO()
        fig.savefig(buf)
        put_image(buf.getvalue())

    if choose_manually:
        put_text(
            "If you repeat this experiment 100 times, the green line should be at the right of blue line at least 95 times."
        )
    else:
        put_text(
            f"If the green line is at the left of blue line, we can 80% sure that the claimed probability is wrong if the real probability is {p1=}"
        )
    plot_prob(0.03, probabilities[3], "Normal Distribution of Gacha Result: 3 Star")
    plot_prob(0.17, probabilities[2], "Normal Distribution of Gacha Result: 2 Star")

    with use_scope("verification"):
        scroll_to("verification")
        put_markdown("# Verification Phase")
        put_button(
            "What is this?",
            onclick=lambda: popup(
                "Phase 4",
                [
                    put_text(
                        "This phase will allow you to verify the correctness of the evaluation against the function commitment. You can enter x and y to verify the proof."
                    ),
                    put_image(phases_images["phase4"]),
                ],
                size="large",
            ),
        )

        def handle_prefill(c):
            c = int(c)
            input_update("x", value=str(xs[c]))
            input_update("y", value=str(ys[c]))
            input_update("pi", value=str(pis[c]))

        while True:
            info = input_group(
                "Verify (Currently this sends the data to the server for verification)",
                [
                    select(
                        "Pre-fill verification with previous evaluation result",
                        options=[str(i) for i in range(len(xs))],
                        onchange=handle_prefill,
                        name="prefill",
                    ),
                    input(
                        "Commitment",
                        type=TEXT,
                        value=str(commitment),
                        name="c",
                    ),
                    input("x", type=TEXT, value=str(x), name="x"),
                    input("y", type=TEXT, value=str(y), name="y"),
                    input("Proof", type=TEXT, value=str(pi), name="pi"),
                ],
            )
            cc = tuple(map(curve.FQ, ast.literal_eval(info["c"])))
            xx = F(int(info["x"]))
            yy = F(int(info["y"]))
            pipi = tuple(map(curve.FQ, ast.literal_eval(info["pi"])))
            if verifyEvalProofRaw(cc, xx, yy, pipi):
                put_text(f"Verify Success with x = {info['x']}, y = {info['y']}")
            else:
                put_text(f"Verify Failed with x = {info['x']}, y = {info['y']}")


if __name__ == "__main__":
    start_server(main, host="0.0.0.0", port=12121, debug=True)
